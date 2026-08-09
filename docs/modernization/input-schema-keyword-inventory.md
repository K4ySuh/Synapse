# Input Schema Keyword Inventory

Measured on 2026-08-09 from the 174 frozen legacy `inputSchema` documents.
Property names are not counted as schema keywords.

| Keyword | Uses | Converter behavior |
| --- | ---: | --- |
| `type` | 1,528 | enforced for strings, integers, numbers, booleans, nulls, arrays, and objects |
| `default` | 405 | preserved; omitted legacy fields retain their documented default behavior |
| `properties` | 177 | recursively converted |
| `minimum` | 170 | enforced |
| `required` | 128 | enforced, except legacy `confirm` remains runtime-optional at the application seam |
| `items` | 78 | recursively enforced for arrays |
| `enum` | 64 | converted to a literal constraint |
| `additionalProperties` | 51 | boolean `true`/omission allows extras; `false` forbids them |
| `maximum` | 41 | enforced |
| `description` | 34 | retained as schema annotation; it does not alter validation |
| `oneOf` | 5 | converted for the five disjoint string/array or string/object unions in the surface |

The converter supports exactly this inventory. It recursively rejects an
unknown keyword instead of silently dropping validation semantics, and rejects
non-boolean `additionalProperties`. Tests cover required/default behavior,
strict scalar types, enums, the used unions, nested objects/arrays,
additional-properties behavior, numeric bounds, reserved internal fields, and
unsupported-keyword failure.

This is not a claim of general JSON Schema 2020-12 compilation. The remaining
168 actions must be migrated only after their explicit Pydantic model or
schema-validation strategy is chosen and tested.
