# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Typed input and output contracts generated from frozen JSON Schema."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, ClassVar, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, JsonValue, create_model, model_validator


SUPPORTED_INPUT_SCHEMA_KEYWORDS = frozenset(
    {
        "type",
        "properties",
        "required",
        "default",
        "enum",
        "oneOf",
        "items",
        "additionalProperties",
        "minimum",
        "maximum",
        "description",
    }
)


@dataclass(frozen=True, slots=True)
class InputContractDocument:
    """The exact authored JSON text for an action's legacy input schema."""

    source: str

    def parsed(self) -> dict[str, Any]:
        """Return the ordered JSON object represented by ``source``."""

        parsed = json.loads(self.source)
        if not isinstance(parsed, dict):
            raise ValueError("An input contract document must contain a JSON object")
        return parsed


class ActionInput(BaseModel):
    """Base class for generated application action inputs."""

    contract_document: ClassVar[InputContractDocument]
    model_config = ConfigDict(strict=True, extra="allow")


class ActionOutput(BaseModel):
    """Base class for typed application action outputs."""


class JsonObjectActionOutput(ActionOutput):
    """Shared outcome fields used by retained JSON-object serializers."""

    background: bool | None = None
    job: dict[str, JsonValue] | None = None
    status: JsonValue | None = None
    result: JsonValue | None = None
    error: JsonValue | None = None
    __pydantic_extra__: dict[str, JsonValue] = Field(init=False)
    model_config = ConfigDict(strict=True, extra="allow")


_OUTPUT_CONTRACTS_PATH = Path(__file__).with_name("output_contracts.json")


def _load_output_contracts() -> dict[str, dict[str, Any]]:
    document = json.loads(_OUTPUT_CONTRACTS_PATH.read_text(encoding="utf-8"))
    contracts = document.get("contracts")
    if document.get("schemaVersion") != 1 or document.get("actionCount") != 168 or not isinstance(contracts, dict):
        raise RuntimeError("retained action output contracts are invalid or incomplete")
    return contracts


OUTPUT_CONTRACTS = _load_output_contracts()


def _fixture_annotation(types: list[str]) -> Any:
    mapping: dict[str, Any] = {
        "array": list[JsonValue],
        "boolean": bool,
        "integer": int,
        "null": type(None),
        "number": Union[int, float],
        "object": dict[str, JsonValue],
        "string": str,
    }
    annotations = [mapping[value] for value in types if value in mapping]
    return _union_of(annotations) if annotations else JsonValue


def make_json_object_output_model(name: str, action_id: str) -> type[ActionOutput]:
    """Create an action-specific model from audited serializer/fixture evidence."""

    declaration = OUTPUT_CONTRACTS[action_id]
    fixture_types = declaration.get("fixtureTypes", {})
    fields: dict[str, tuple[Any, Any]] = {}
    for index, public_name in enumerate(declaration["fields"]):
        internal_name = re.sub(r"\W", "_", public_name)
        if not internal_name.isidentifier() or internal_name in JsonObjectActionOutput.model_fields:
            internal_name = f"declared_field_{index}"
        annotation = _fixture_annotation(list(fixture_types.get(public_name, [])))
        fields[internal_name] = (annotation | None, Field(default=None, alias=public_name))

    configured_base = type(
        f"{name}ConfiguredBase",
        (JsonObjectActionOutput,),
        {
            "model_config": ConfigDict(
                strict=True,
                extra="allow",
                populate_by_name=True,
                json_schema_extra={
                    "x-synapse-action-id": action_id,
                    "x-synapse-contract-sources": declaration["sources"],
                    "x-synapse-dynamic-boundary": declaration["dynamicBoundary"],
                },
            )
        },
    )
    return create_model(name, __base__=configured_base, **fields)


def _union_of(annotations: list[Any]) -> Any:
    if not annotations:
        return Any
    if len(annotations) == 1:
        return annotations[0]
    return Union[tuple(annotations)]


def _literal_of(values: list[Any]) -> Any:
    if not values:
        return Any
    return Literal[tuple(values)]


def validate_supported_input_schema(schema: dict[str, Any], *, location: str = "$") -> None:
    """Reject schemas whose validation semantics the converter cannot preserve."""

    unsupported = sorted(set(schema) - SUPPORTED_INPUT_SCHEMA_KEYWORDS)
    if unsupported:
        joined = ", ".join(unsupported)
        raise ValueError(f"Unsupported input schema keyword(s) at {location}: {joined}")

    additional = schema.get("additionalProperties", True)
    if not isinstance(additional, bool):
        raise ValueError(f"additionalProperties must be boolean at {location}")

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError(f"properties must be an object at {location}")
    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            raise ValueError(f"Property schema must be an object at {location}.properties.{field_name}")
        validate_supported_input_schema(field_schema, location=f"{location}.properties.{field_name}")

    items = schema.get("items")
    if items is not None:
        if not isinstance(items, dict):
            raise ValueError(f"items must be an object at {location}")
        validate_supported_input_schema(items, location=f"{location}.items")

    alternatives = schema.get("oneOf")
    if alternatives is not None:
        if not isinstance(alternatives, list) or not alternatives:
            raise ValueError(f"oneOf must be a non-empty array at {location}")
        for index, alternative in enumerate(alternatives):
            if not isinstance(alternative, dict):
                raise ValueError(f"oneOf entries must be objects at {location}.oneOf[{index}]")
            validate_supported_input_schema(alternative, location=f"{location}.oneOf[{index}]")


def _annotation_for_schema(schema: dict[str, Any], model_name: str) -> Any:
    alternatives = schema.get("oneOf")
    if isinstance(alternatives, list):
        return _union_of(
            [
                _annotation_for_schema(alternative, f"{model_name}Alternative{index + 1}")
                for index, alternative in enumerate(alternatives)
                if isinstance(alternative, dict)
            ]
        )

    allowed = schema.get("enum")
    if isinstance(allowed, list):
        return _literal_of(allowed)

    expected = schema.get("type")
    if expected == "string":
        return str
    if expected == "integer":
        return int
    if expected == "number":
        return Union[int, float]
    if expected == "boolean":
        return bool
    if expected == "null":
        return type(None)
    if expected == "array":
        item_schema = schema.get("items")
        item_annotation = (
            _annotation_for_schema(item_schema, f"{model_name}Item") if isinstance(item_schema, dict) else Any
        )
        return list[item_annotation]
    if expected == "object":
        return _make_object_model(model_name, schema, relax_required_confirm=False)
    return Any


def _field_default(schema: dict[str, Any], *, required: bool) -> Any:
    if "default" in schema:
        default: Any = schema["default"]
    elif required:
        default = ...
    else:
        default = None

    constraints: dict[str, Any] = {}
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if isinstance(minimum, (int, float)) and not isinstance(minimum, bool):
        constraints["ge"] = minimum
    if isinstance(maximum, (int, float)) and not isinstance(maximum, bool):
        constraints["le"] = maximum
    description = schema.get("description")
    if isinstance(description, str):
        constraints["description"] = description
    return Field(default=default, **constraints)


def _make_object_model(
    name: str,
    schema: dict[str, Any],
    *,
    relax_required_confirm: bool,
    validators: dict[str, Any] | None = None,
    base: type[BaseModel] | None = None,
) -> type[BaseModel]:
    properties = schema.get("properties")
    property_schemas = properties if isinstance(properties, dict) else {}
    required_value = schema.get("required")
    required = {field for field in required_value if isinstance(field, str)} if isinstance(required_value, list) else set()

    field_names = list(property_schemas)
    field_names.extend(field for field in required if field not in property_schemas)
    fields: dict[str, tuple[Any, Any]] = {}
    for field_name in field_names:
        field_schema = property_schemas.get(field_name)
        typed_schema = field_schema if isinstance(field_schema, dict) else {}
        runtime_required = field_name in required and not (relax_required_confirm and field_name == "confirm")
        annotation = _annotation_for_schema(typed_schema, f"{name}{field_name.title().replace('_', '')}")
        fields[field_name] = (annotation, _field_default(typed_schema, required=runtime_required))

    extra_behavior = "allow" if schema.get("additionalProperties", True) else "forbid"
    model_options: dict[str, Any] = {
        "__config__": ConfigDict(strict=True, extra=extra_behavior),
        "__validators__": validators or {},
    }
    if base is not None:
        model_options.pop("__config__")
        configured_base = type(
            f"{name}ConfiguredBase",
            (base,),
            {"model_config": ConfigDict(strict=True, extra=extra_behavior)},
        )
        model_options["__base__"] = configured_base
    return create_model(name, **model_options, **fields)


def make_input_model(name: str, document: InputContractDocument) -> type[BaseModel]:
    """Build a strict input model from one frozen legacy contract document."""

    schema = document.parsed()
    validate_supported_input_schema(schema)

    def reject_reserved_fields(value: Any) -> Any:
        if isinstance(value, dict):
            reserved = next((field for field in value if isinstance(field, str) and field.startswith("_")), None)
            if reserved is not None:
                raise ValueError(f"field {reserved} is reserved for internal workers")
        return value

    reserved_validator = model_validator(mode="before")(reject_reserved_fields)
    model = _make_object_model(
        name,
        schema,
        relax_required_confirm=True,
        validators={"reject_reserved_fields": reserved_validator},
        base=ActionInput,
    )
    model.contract_document = document
    return model
