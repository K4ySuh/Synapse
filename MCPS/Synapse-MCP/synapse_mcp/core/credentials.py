# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import json
import os
import re
import time
from typing import Any, Callable, TypeVar
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from . import atomic_io, evidence, scope
from .errors import McpError
from .http import HttpClientPolicy, HttpRequest, http_client
from .paths import DATA_DIR, synapse_python


CREDENTIALS_FILE = DATA_DIR / "credentials" / "credentials.json"
SUPPORTED_TYPES = {"bearer", "basic", "cookie", "header", "session"}
SUPPORTED_AUTH_CONTENT_TYPES = {"form", "json"}
SUPPORTED_BROWSER_PROVIDERS = {"playwright", "selenium_remote"}
SUPPORTED_BROWSER_ENGINES = {"chromium", "firefox", "webkit"}
SUPPORTED_BROWSER_STEP_ACTIONS = {
    "goto",
    "fill",
    "click",
    "press",
    "select",
    "check",
    "uncheck",
    "wait_for_url",
    "wait_for_selector",
    "wait_for_load_state",
}
ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
HTTP_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
DEFAULT_USERNAME_SELECTORS = [
    "input[name='username']",
    "input[name='user']",
    "input[name='email']",
    "input[type='email']",
    "#username",
    "#user",
    "#email",
]
DEFAULT_PASSWORD_SELECTORS = ["input[name='password']", "input[type='password']", "#password"]
DEFAULT_SUBMIT_SELECTORS = [
    "button[type='submit']",
    "input[type='submit']",
    "button:has-text('Sign in')",
    "button:has-text('Log in')",
    "button:has-text('Login')",
]
DEFAULT_AUTH_TIMEOUT_SECONDS = 1800
DEFAULT_AUTH_REQUEST_TIMEOUT_SECONDS = 45
SESSION_BROWSER_HEADER_ALLOWLIST = {"User-Agent", "Accept-Language", "Accept"}
TMutationResult = TypeVar("TMutationResult")


def auth_process_guidance() -> dict[str, Any]:
    return {
        "message": (
            "If this target uses authentication, ask the operator to describe the login flow before storing "
            "credentials or running active authenticated tooling."
        ),
        "requestedDetails": [
            "login URL and whether the flow is single-step or multi-step",
            "required fields such as username, password, CSRF token, tenant, MFA code, or hidden form values",
            "where dynamic values come from, for example a pre-login page, API response, Burp history item, or manual operator input",
            "success and failure indicators such as redirect target, status code, page text, or response JSON field",
            "cookie names or headers that represent the authenticated session",
            "whether MFA, SSO, SAML/OIDC, CAPTCHA, device approval, or other manual steps are involved",
        ],
        "safeSubmission": (
            "Send reusable secrets only through credentials.set or credentials.set_auth_profile with confirm=true. "
            "For complex or multi-step flows, provide a redacted Burp history export, exact request IDs, or "
            "operator notes describing each step instead of pasting secrets into evidence."
        ),
        "supportedAutomation": [
            "Static form or JSON login can be represented with credentials.set_auth_profile.",
            "Browser-assisted and Playwright-scripted flows can be represented with credentials.set_browser_auth_profile.",
            "MFA, SSO, SAML/OIDC, CAPTCHA, or device approval flows should use headed browser-assisted mode with explicit operator approval.",
        ],
    }


def _load_credentials_unlocked() -> dict[str, Any]:
    if not CREDENTIALS_FILE.exists():
        return {"credentials": [], "authProfiles": []}
    try:
        payload = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"credentials": [], "warnings": [f"Invalid credentials file: {CREDENTIALS_FILE}"]}
    if not isinstance(payload, dict) or not isinstance(payload.get("credentials"), list):
        return {"credentials": [], "warnings": [f"Invalid credentials schema: {CREDENTIALS_FILE}"]}
    payload.setdefault("authProfiles", [])
    return payload


def load_credentials() -> dict[str, Any]:
    with atomic_io.file_lock(CREDENTIALS_FILE):
        return _load_credentials_unlocked()


def _write_credentials_unlocked(payload: dict[str, Any]) -> None:
    atomic_io.atomic_write_text(
        CREDENTIALS_FILE,
        json.dumps(payload, indent=2),
        mode=0o600,
        fsync=True,
    )


def _mutate_credentials(
    mutation: Callable[[dict[str, Any]], TMutationResult],
) -> TMutationResult:
    """Apply one credentials/profile read-modify-write cycle under one lock."""

    with atomic_io.file_lock(CREDENTIALS_FILE):
        payload = _load_credentials_unlocked()
        result = mutation(payload)
        _write_credentials_unlocked(payload)
        return result


def _write_private_json(path: Any, payload: dict[str, Any]) -> None:
    with atomic_io.file_lock(path):
        atomic_io.atomic_write_text(
            path,
            json.dumps(payload, indent=2, ensure_ascii=False),
            mode=0o600,
            fsync=True,
        )


def _strip_worker_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        stripped: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).strip().lower() in {"password", "secret", "token"}:
                continue
            stripped[key] = _strip_worker_secrets(item)
        return stripped
    if isinstance(value, list):
        return [_strip_worker_secrets(item) for item in value]
    return value


def _redact_value(value: str) -> str:
    if not value:
        return ""
    if len(value) < 20:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def redact_credential(record: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(record)
    if "secret" in redacted:
        redacted["secret"] = _redact_value(str(redacted["secret"]))
    if "password" in redacted:
        redacted["password"] = _redact_value(str(redacted["password"]))
    return redacted


def redact_auth_profile(record: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(record)
    if "password" in redacted:
        redacted["password"] = _redact_value(str(redacted["password"]))
    if isinstance(redacted.get("steps"), list):
        redacted["steps"] = [_redact_step(item) for item in redacted["steps"]]
    return redacted


def _redact_step(step: Any) -> Any:
    if not isinstance(step, dict):
        return step
    redacted = dict(step)
    for key in ("value", "text"):
        value = str(redacted.get(key, ""))
        if any(marker in value.lower() for marker in ("{{password}}", "{{secret}}", "{{token}}")):
            redacted[key] = "[REDACTED]"
    return redacted


def list_credentials(include_secrets: bool = False) -> dict[str, Any]:
    payload = load_credentials()
    records = payload.get("credentials", [])
    profiles = payload.get("authProfiles", [])
    visible = records if include_secrets else [redact_credential(item) for item in records]
    visible_profiles = profiles if include_secrets else [redact_auth_profile(item) for item in profiles]
    return {
        "path": str(CREDENTIALS_FILE),
        "credentials": visible,
        "authProfiles": visible_profiles,
        "redacted": not include_secrets,
        **({"warnings": payload["warnings"]} if payload.get("warnings") else {}),
    }


def _normalize_scopes(values: list[str]) -> list[str]:
    normalized = sorted({scope.normalize_host(value) for value in values if scope.normalize_host(value)})
    if not normalized:
        raise McpError(-32602, "Credential scopes must include at least one hostname or URL.")
    known_scope = set(scope.load_scope().get("hosts", []))
    unknown = [host for host in normalized if host not in known_scope]
    if unknown:
        raise McpError(-32002, f"Credential scopes are not in authorized scope: {', '.join(unknown)}")
    return normalized


def _validate_record(args: dict[str, Any]) -> dict[str, Any]:
    credential_id = str(args.get("id", "")).strip()
    if not ID_RE.fullmatch(credential_id):
        raise McpError(-32602, "Credential id must be 1-80 characters: letters, numbers, dot, underscore, or dash.")
    credential_type = str(args.get("type", "")).strip().lower()
    if credential_type not in SUPPORTED_TYPES:
        raise McpError(-32602, f"Credential type must be one of: {', '.join(sorted(SUPPORTED_TYPES))}.")
    record: dict[str, Any] = {
        "id": credential_id,
        "type": credential_type,
        "scopes": _normalize_scopes(args.get("scopes", [])),
        "label": str(args.get("label", "")).strip(),
    }
    secret = str(args.get("secret", ""))
    if not secret:
        raise McpError(-32602, "Credential secret is required.")
    record["secret"] = secret
    if credential_type == "basic":
        username = str(args.get("username", "")).strip()
        if not username:
            raise McpError(-32602, "Basic credentials require username.")
        record["username"] = username
    if credential_type == "header":
        header_name = str(args.get("headerName", "")).strip()
        if not header_name:
            raise McpError(-32602, "Header credentials require headerName.")
        if "\r" in header_name or "\n" in header_name or not HTTP_HEADER_NAME_RE.fullmatch(header_name):
            raise McpError(-32602, "Header credential headerName must be a valid HTTP token and must not contain CR/LF.")
        if "\r" in secret or "\n" in secret:
            raise McpError(-32602, "Header credential secret must not contain CR/LF.")
        record["headerName"] = header_name
    return record


def _upsert_credential(record: dict[str, Any]) -> None:
    def upsert(payload: dict[str, Any]) -> None:
        records = [item for item in payload.get("credentials", []) if item.get("id") != record["id"]]
        records.append(record)
        records.sort(key=lambda item: str(item.get("id", "")))
        payload["credentials"] = records

    _mutate_credentials(upsert)


def save_credential(args: dict[str, Any]) -> dict[str, Any]:
    record = _validate_record(args)
    _upsert_credential(record)
    evidence.log_event(
        "credentials.set",
        f"Stored credential {record['id']} for {len(record['scopes'])} scoped host(s).",
        {"id": record["id"], "type": record["type"], "scopes": record["scopes"]},
    )
    return {"saved": True, "path": str(CREDENTIALS_FILE), "credential": redact_credential(record)}


def delete_credential(credential_id: str) -> dict[str, Any]:
    def delete(payload: dict[str, Any]) -> tuple[bool, list[str]]:
        before = payload.get("credentials", [])
        profiles_before = payload.get("authProfiles", [])
        after = [item for item in before if item.get("id") != credential_id]
        deleted_credential = len(after) != len(before)
        deleted_profiles = [
            str(item.get("id", ""))
            for item in profiles_before
            if item.get("id") == credential_id or item.get("credentialId") == credential_id
        ]
        payload["credentials"] = after
        payload["authProfiles"] = [
            item
            for item in profiles_before
            if item.get("id") != credential_id and item.get("credentialId") != credential_id
        ]
        return deleted_credential, deleted_profiles

    deleted_credential, deleted_profiles = _mutate_credentials(delete)
    deleted = deleted_credential or bool(deleted_profiles)
    if deleted:
        evidence.log_event(
            "credentials.delete",
            f"Deleted credential/profile reference {credential_id}.",
            {"id": credential_id, "deletedCredential": deleted_credential, "deletedProfiles": deleted_profiles},
        )
    return {
        "deleted": deleted,
        "deletedCredential": deleted_credential,
        "deletedProfiles": deleted_profiles,
        "id": credential_id,
        "path": str(CREDENTIALS_FILE),
    }


def get_credential(credential_id: str, *, include_secret: bool = False) -> dict[str, Any]:
    for record in load_credentials().get("credentials", []):
        if record.get("id") == credential_id:
            return dict(record) if include_secret else redact_credential(record)
    raise McpError(-32602, f"Credential not found: {credential_id}")


def credential_for_target(credential_id: str, target: str) -> dict[str, Any]:
    record = get_credential(credential_id, include_secret=True)
    host = scope.normalize_host(target)
    if host not in set(record.get("scopes", [])):
        raise McpError(-32002, f"Credential {credential_id} is not scoped for target host: {host}")
    return record


def headers_for_credential(record: dict[str, Any]) -> dict[str, str]:
    credential_type = record.get("type")
    secret = str(record.get("secret", ""))
    if credential_type == "bearer":
        return {"Authorization": f"Bearer {secret}"}
    if credential_type == "basic":
        token = base64.b64encode(f"{record.get('username', '')}:{secret}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}
    if credential_type == "cookie":
        return {"Cookie": secret}
    if credential_type == "header":
        return {str(record.get("headerName", "")): secret}
    if credential_type == "session":
        return _headers_for_session_credential(record, "")
    raise McpError(-32602, f"Unsupported credential type: {credential_type}")


def headers_for_credential_target(record: dict[str, Any], target: str) -> dict[str, str]:
    if record.get("type") == "session":
        return _headers_for_session_credential(record, target)
    return headers_for_credential(record)


def redacted_headers_for_credential(record: dict[str, Any]) -> dict[str, str]:
    return {name: _redact_value(value) for name, value in headers_for_credential(record).items()}


def redacted_headers_for_credential_target(record: dict[str, Any], target: str) -> dict[str, str]:
    return {name: _redact_value(value) for name, value in headers_for_credential_target(record, target).items()}


def _headers_for_session_credential(record: dict[str, Any], target: str) -> dict[str, str]:
    bundle = _session_bundle(record)
    headers: dict[str, str] = {}
    cookie_header = _session_cookie_header(bundle, target)
    if cookie_header:
        headers["Cookie"] = cookie_header
    auth = bundle.get("authorization")
    if isinstance(auth, dict):
        scheme = str(auth.get("scheme", "")).strip()
        value = str(auth.get("value", ""))
        if scheme and value:
            headers["Authorization"] = f"{scheme} {value}"
    extra_headers = bundle.get("headers", {})
    if isinstance(extra_headers, dict):
        for name, value in extra_headers.items():
            name_text = str(name).strip()
            value_text = str(value)
            if name_text.lower() in {"authorization", "cookie", "set-cookie"}:
                continue
            if name_text and HTTP_HEADER_NAME_RE.fullmatch(name_text) and "\r" not in value_text and "\n" not in value_text:
                headers[name_text] = value_text
    return headers


def _session_bundle(record: dict[str, Any]) -> dict[str, Any]:
    secret = record.get("secret", {})
    if isinstance(secret, dict):
        return secret
    try:
        payload = json.loads(str(secret))
    except json.JSONDecodeError as exc:
        raise McpError(-32602, f"Invalid session credential bundle for {record.get('id')}.") from exc
    if not isinstance(payload, dict):
        raise McpError(-32602, f"Invalid session credential bundle for {record.get('id')}.")
    return payload


def _session_cookie_header(bundle: dict[str, Any], target: str) -> str:
    cookies = bundle.get("cookies", [])
    if not isinstance(cookies, list):
        return ""
    parsed = urlsplit(target if "://" in target else f"https://{target}") if target else None
    host = (parsed.hostname or "").lower() if parsed else ""
    path = parsed.path or "/" if parsed else "/"
    pairs: list[str] = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name", "")).strip()
        value = str(cookie.get("value", ""))
        if not name:
            continue
        domain = str(cookie.get("domain", "")).lstrip(".").lower()
        cookie_path = str(cookie.get("path", "/") or "/")
        if not domain:
            continue
        if host and not (host == domain or host.endswith(f".{domain}")):
            continue
        if path and cookie_path and not path.startswith(cookie_path.rstrip("/") or "/"):
            continue
        pairs.append(f"{name}={value}")
    return "; ".join(sorted(pairs))


def _validate_auth_profile(args: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(args.get("id", "")).strip()
    if not ID_RE.fullmatch(profile_id):
        raise McpError(-32602, "Authentication profile id must be 1-80 characters: letters, numbers, dot, underscore, or dash.")
    credential_id = str(args.get("credentialId", "")).strip()
    if not ID_RE.fullmatch(credential_id):
        raise McpError(-32602, "credentialId must be 1-80 characters: letters, numbers, dot, underscore, or dash.")
    login_url = str(args.get("loginUrl", "")).strip()
    login_host = scope.normalize_host(login_url)
    if not login_host:
        raise McpError(-32602, "loginUrl must include a hostname.")
    scopes = _normalize_scopes(args.get("scopes", [login_host]))
    if login_host not in scopes:
        raise McpError(-32002, f"loginUrl host must be included in authentication scopes: {login_host}")

    content_type = str(args.get("contentType", "form")).strip().lower()
    if content_type not in SUPPORTED_AUTH_CONTENT_TYPES:
        raise McpError(-32602, f"contentType must be one of: {', '.join(sorted(SUPPORTED_AUTH_CONTENT_TYPES))}.")
    method = str(args.get("method", "POST")).strip().upper()
    if method not in {"POST", "GET"}:
        raise McpError(-32602, "Authentication method must be GET or POST.")
    if method == "GET" and args.get("allowCredentialInUrl") is not True:
        raise McpError(
            -32001,
            "GET authentication puts credentials in the URL; set allowCredentialInUrl=true after explicit operator approval.",
        )

    username = str(args.get("username", ""))
    password = str(args.get("password", ""))
    if not username or not password:
        raise McpError(-32602, "Authentication profiles require username and password.")
    username_field = str(args.get("usernameField", "username")).strip()
    password_field = str(args.get("passwordField", "password")).strip()
    if not username_field or not password_field:
        raise McpError(-32602, "usernameField and passwordField are required.")

    extra_fields = args.get("extraFields", {})
    if extra_fields is None:
        extra_fields = {}
    if not isinstance(extra_fields, dict):
        raise McpError(-32602, "extraFields must be an object.")
    success_status_codes = args.get("successStatusCodes", [200, 201, 202, 204, 302, 303])
    if not isinstance(success_status_codes, list) or not all(isinstance(item, int) for item in success_status_codes):
        raise McpError(-32602, "successStatusCodes must be an array of integers.")

    cookie_names = args.get("cookieNames", [])
    if cookie_names is None:
        cookie_names = []
    if not isinstance(cookie_names, list) or not all(isinstance(item, str) for item in cookie_names):
        raise McpError(-32602, "cookieNames must be an array of strings.")

    return {
        "id": profile_id,
        "credentialId": credential_id,
        "type": "http_login",
        "scopes": scopes,
        "loginUrl": login_url,
        "method": method,
        "allowCredentialInUrl": bool(args.get("allowCredentialInUrl")),
        "contentType": content_type,
        "username": username,
        "password": password,
        "usernameField": username_field,
        "passwordField": password_field,
        "extraFields": extra_fields,
        "cookieNames": sorted({name for name in cookie_names if name.strip()}),
        "successStatusCodes": success_status_codes,
        "successPattern": str(args.get("successPattern", "")),
        "failurePattern": str(args.get("failurePattern", "")),
        "label": str(args.get("label", "")).strip(),
    }


def save_auth_profile(args: dict[str, Any]) -> dict[str, Any]:
    profile = _validate_auth_profile(args)
    def upsert(payload: dict[str, Any]) -> None:
        profiles = [item for item in payload.get("authProfiles", []) if item.get("id") != profile["id"]]
        profiles.append(profile)
        profiles.sort(key=lambda item: str(item.get("id", "")))
        payload["authProfiles"] = profiles

    _mutate_credentials(upsert)
    evidence.log_event(
        "credentials.auth_profile.set",
        f"Stored authentication profile {profile['id']} for credential {profile['credentialId']}.",
        {
            "id": profile["id"],
            "credentialId": profile["credentialId"],
            "scopes": profile["scopes"],
            "loginHost": scope.normalize_host(profile["loginUrl"]),
        },
    )
    return {"saved": True, "path": str(CREDENTIALS_FILE), "authProfile": redact_auth_profile(profile)}


def _validate_browser_auth_profile(args: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(args.get("id", "")).strip()
    if not ID_RE.fullmatch(profile_id):
        raise McpError(-32602, "Browser authentication profile id must be 1-80 characters: letters, numbers, dot, underscore, or dash.")
    credential_id = str(args.get("credentialId", "")).strip()
    if not ID_RE.fullmatch(credential_id):
        raise McpError(-32602, "credentialId must be 1-80 characters: letters, numbers, dot, underscore, or dash.")
    login_url = str(args.get("loginUrl", "")).strip()
    login_host = scope.normalize_host(login_url)
    if not login_host:
        raise McpError(-32602, "loginUrl must include a hostname.")
    scopes = _normalize_scopes(args.get("scopes", [login_host]))
    if login_host not in scopes:
        raise McpError(-32002, f"loginUrl host must be included in authentication scopes: {login_host}")
    provider = str(args.get("provider", "playwright")).strip().lower()
    if provider not in SUPPORTED_BROWSER_PROVIDERS:
        raise McpError(-32602, f"provider must be one of: {', '.join(sorted(SUPPORTED_BROWSER_PROVIDERS))}.")
    browser = str(args.get("browser", "chromium")).strip().lower()
    if browser not in SUPPORTED_BROWSER_ENGINES:
        raise McpError(-32602, f"browser must be one of: {', '.join(sorted(SUPPORTED_BROWSER_ENGINES))}.")
    if provider == "selenium_remote" and browser == "webkit":
        raise McpError(-32602, "selenium_remote supports chromium or firefox; use provider=playwright for webkit.")
    username = str(args.get("username", ""))
    password = str(args.get("password", ""))
    manual_completion = bool(args.get("manualCompletion", False))
    if not manual_completion and not args.get("steps") and (not username or not password):
        raise McpError(-32602, "Browser authentication profiles require username and password unless manualCompletion=true or explicit steps are supplied.")
    steps = _validate_browser_steps(args.get("steps", []))
    success_status_codes = args.get("successStatusCodes", [200, 204, 302, 303])
    if not isinstance(success_status_codes, list) or not all(isinstance(item, int) for item in success_status_codes):
        raise McpError(-32602, "successStatusCodes must be an array of integers.")
    cookie_names = args.get("cookieNames", [])
    if cookie_names is None:
        cookie_names = []
    if not isinstance(cookie_names, list) or not all(isinstance(item, str) for item in cookie_names):
        raise McpError(-32602, "cookieNames must be an array of strings.")
    token_storage_keys = args.get("tokenStorageKeys", [])
    if token_storage_keys is None:
        token_storage_keys = []
    if not isinstance(token_storage_keys, list) or not all(isinstance(item, str) for item in token_storage_keys):
        raise McpError(-32602, "tokenStorageKeys must be an array of strings.")
    username_selectors = _string_list(args.get("usernameSelectors", DEFAULT_USERNAME_SELECTORS), "usernameSelectors")
    password_selectors = _string_list(args.get("passwordSelectors", DEFAULT_PASSWORD_SELECTORS), "passwordSelectors")
    submit_selectors = _string_list(args.get("submitSelectors", DEFAULT_SUBMIT_SELECTORS), "submitSelectors")
    protected_url = str(args.get("protectedUrl", "")).strip()
    if protected_url and scope.normalize_host(protected_url) not in set(scopes):
        raise McpError(-32002, f"protectedUrl host must be included in authentication scopes: {scope.normalize_host(protected_url)}")
    return {
        "id": profile_id,
        "credentialId": credential_id,
        "type": "browser_auth",
        "scopes": scopes,
        "loginUrl": login_url,
        "provider": provider,
        "browser": browser,
        "remoteUrl": str(args.get("remoteUrl", "")).strip(),
        "headless": bool(args.get("headless", not manual_completion)),
        "manualCompletion": manual_completion,
        "username": username,
        "password": password,
        "usernameSelectors": username_selectors,
        "passwordSelectors": password_selectors,
        "submitSelectors": submit_selectors,
        "steps": steps,
        "successUrlPattern": str(args.get("successUrlPattern", "")).strip(),
        "successSelector": str(args.get("successSelector", "")).strip(),
        "successPattern": str(args.get("successPattern", "")).strip(),
        "failurePattern": str(args.get("failurePattern", "")).strip(),
        "protectedUrl": protected_url,
        "successStatusCodes": success_status_codes,
        "cookieNames": sorted({name for name in cookie_names if name.strip()}),
        "captureStorage": bool(args.get("captureStorage", True)),
        "tokenStorageKeys": sorted({name for name in token_storage_keys if name.strip()}),
        "authorizationStorageKey": str(args.get("authorizationStorageKey", "")).strip(),
        "authorizationScheme": str(args.get("authorizationScheme", "Bearer")).strip() or "Bearer",
        "captureBrowserHeaders": bool(args.get("captureBrowserHeaders", True)),
        "label": str(args.get("label", "")).strip(),
    }


def _string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise McpError(-32602, f"{label} must be an array of strings.")
    return [item for item in value if item.strip()]


def _validate_browser_steps(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise McpError(-32602, "steps must be an array.")
    steps: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise McpError(-32602, f"Browser auth step {index} must be an object.")
        action = str(item.get("action", "")).strip().lower()
        if action not in SUPPORTED_BROWSER_STEP_ACTIONS:
            raise McpError(-32602, f"Unsupported browser auth step action at index {index}: {action}")
        step: dict[str, Any] = {"action": action}
        for key in ("selector", "value", "url", "text", "key", "state"):
            if key in item:
                step[key] = str(item.get(key, ""))
        if "timeoutMillis" in item:
            step["timeoutMillis"] = max(int(item.get("timeoutMillis") or 0), 0)
        steps.append(step)
    return steps


def save_browser_auth_profile(args: dict[str, Any]) -> dict[str, Any]:
    profile = _validate_browser_auth_profile(args)
    def upsert(payload: dict[str, Any]) -> None:
        profiles = [item for item in payload.get("authProfiles", []) if item.get("id") != profile["id"]]
        profiles.append(profile)
        profiles.sort(key=lambda item: str(item.get("id", "")))
        payload["authProfiles"] = profiles

    _mutate_credentials(upsert)
    evidence.log_event(
        "credentials.browser_auth_profile.set",
        f"Stored browser authentication profile {profile['id']} for credential {profile['credentialId']}.",
        {
            "id": profile["id"],
            "credentialId": profile["credentialId"],
            "scopes": profile["scopes"],
            "loginHost": scope.normalize_host(profile["loginUrl"]),
            "provider": profile["provider"],
            "manualCompletion": profile["manualCompletion"],
        },
    )
    return {"saved": True, "path": str(CREDENTIALS_FILE), "authProfile": redact_auth_profile(profile)}


def get_auth_profile(profile_id: str, *, include_secret: bool = False) -> dict[str, Any]:
    for profile in load_credentials().get("authProfiles", []):
        if profile.get("id") == profile_id:
            return dict(profile) if include_secret else redact_auth_profile(profile)
    raise McpError(-32602, f"Authentication profile not found: {profile_id}")


def _auth_request_body(profile: dict[str, Any]) -> tuple[bytes | None, dict[str, str]]:
    fields = dict(profile.get("extraFields", {}))
    fields[str(profile["usernameField"])] = profile["username"]
    fields[str(profile["passwordField"])] = profile["password"]
    if profile["method"] == "GET":
        return None, {}
    if profile["contentType"] == "json":
        return json.dumps(fields).encode("utf-8"), {"Content-Type": "application/json"}
    return urlencode(fields).encode("utf-8"), {"Content-Type": "application/x-www-form-urlencoded"}


def _auth_url(profile: dict[str, Any]) -> str:
    if profile["method"] != "GET":
        return str(profile["loginUrl"])
    fields = dict(profile.get("extraFields", {}))
    fields[str(profile["usernameField"])] = profile["username"]
    fields[str(profile["passwordField"])] = profile["password"]
    separator = "&" if "?" in profile["loginUrl"] else "?"
    return f"{profile['loginUrl']}{separator}{urlencode(fields)}"


def _cookie_header(cookies: list[dict[str, str]], login_url: str, names: list[str]) -> str:
    login_host = urlsplit(login_url).hostname or ""
    allowed = set(names)
    pairs = []
    for cookie in cookies:
        name = str(cookie.get("name", ""))
        if allowed and name not in allowed:
            continue
        domain = str(cookie.get("domain", "")).lstrip(".")
        domain_specified = str(cookie.get("domainSpecified", "")).lower() == "true"
        local_domain_match = domain.endswith(".local") and login_host == domain[: -len(".local")]
        if domain_specified and domain and login_host and not (login_host == domain or login_host.endswith(f".{domain}") or local_domain_match):
            continue
        pairs.append(f"{name}={cookie.get('value', '')}")
    return "; ".join(sorted(pairs))


def authenticate(args: dict[str, Any]) -> dict[str, Any]:
    profile = get_auth_profile(str(args["profileId"]), include_secret=True)
    target = str(args.get("target") or profile["loginUrl"])
    host = scope.normalize_host(target)
    if host not in set(profile.get("scopes", [])):
        raise McpError(-32002, f"Authentication profile {profile['id']} is not scoped for target host: {host}")

    body, headers = _auth_request_body(profile)
    response = http_client.send(
        HttpRequest(
            url=_auth_url(profile),
            method=profile["method"],
            headers={"Accept": "text/html,application/json,*/*", **headers},
            body=body,
        ),
        policy=HttpClientPolicy.from_args(
            {
                **args,
                "maxBodyBytes": int(args.get("maxBodyBytes", 250_000)),
            },
            timeout_seconds=int(args.get("requestTimeout", 15)),
        ),
    )
    if response.status is None:
        raise McpError(-32000, f"Authentication request failed: {response.error}")
    response_status = response.status
    response_body = response.body

    success_codes = set(profile.get("successStatusCodes", []))
    failure_pattern = str(profile.get("failurePattern", ""))
    success_pattern = str(profile.get("successPattern", ""))
    if response_status not in success_codes:
        raise McpError(-32000, f"Authentication failed with HTTP status {response_status}.")
    if failure_pattern and re.search(failure_pattern, response_body, re.I):
        raise McpError(-32000, "Authentication response matched the configured failurePattern.")
    if success_pattern and not re.search(success_pattern, response_body, re.I):
        raise McpError(-32000, "Authentication response did not match the configured successPattern.")

    cookie_header = _cookie_header(response.cookies, profile["loginUrl"], profile.get("cookieNames", []))
    if not cookie_header:
        raise McpError(-32000, "Authentication succeeded but no matching cookies were returned.")

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    credential = {
        "id": profile["credentialId"],
        "type": "cookie",
        "scopes": profile["scopes"],
        "label": profile.get("label") or f"Authenticated cookie from {profile['id']}",
        "secret": cookie_header,
        "authProfileId": profile["id"],
        "issuedAt": now,
        "lastAuthenticatedAt": now,
    }
    _upsert_credential(credential)
    evidence.log_event(
        "credentials.authenticate",
        f"Authenticated profile {profile['id']} and refreshed credential {credential['id']}.",
        {
            "profileId": profile["id"],
            "credentialId": credential["id"],
            "target": host,
            "loginHost": scope.normalize_host(profile["loginUrl"]),
            "status": response_status,
            "cookieNames": [part.split("=", 1)[0] for part in cookie_header.split("; ")],
        },
    )
    return {
        "authenticated": True,
        "profileId": profile["id"],
        "credential": redact_credential(credential),
        "status": response_status,
        "cookieNames": [part.split("=", 1)[0] for part in cookie_header.split("; ")],
    }


def browser_auth_check_setup(args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    provider = str(args.get("provider", "playwright")).strip().lower()
    checks: dict[str, Any] = {"provider": provider, "ok": False, "checks": []}
    if provider == "playwright":
        try:
            from playwright.sync_api import sync_playwright  # type: ignore

            checks["checks"].append({"name": "playwright_package", "ok": True})
        except Exception as exc:
            checks["checks"].append(
                {
                    "name": "playwright_package",
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "remediation": "Install the optional browser dependency and browser binaries, for example: python3 -m pip install '.[browser]' && python3 -m playwright install chromium",
                }
            )
            return checks
        browser = str(args.get("browser", "chromium")).strip().lower()
        if browser not in SUPPORTED_BROWSER_ENGINES:
            checks["checks"].append({"name": "browser", "ok": False, "error": f"Unsupported browser: {browser}"})
            return checks
        try:
            with sync_playwright() as pw:
                engine = getattr(pw, browser)
                launched = engine.launch(headless=True)
                launched.close()
            checks["checks"].append({"name": "browser_launch", "ok": True, "browser": browser})
        except Exception as exc:
            checks["checks"].append(
                {
                    "name": "browser_launch",
                    "ok": False,
                    "browser": browser,
                    "error": f"{type(exc).__name__}: {exc}",
                    "remediation": f"Install Playwright browser binaries: python3 -m playwright install {browser}",
                }
            )
            return checks
        checks["ok"] = True
        return checks
    if provider == "selenium_remote":
        try:
            import selenium  # type: ignore  # noqa: F401

            checks["checks"].append({"name": "selenium_package", "ok": True})
        except Exception as exc:
            checks["checks"].append(
                {
                    "name": "selenium_package",
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "remediation": "Install the optional browser dependency, for example: python3 -m pip install '.[browser]'",
                }
            )
            return checks
        remote_url = str(args.get("remoteUrl", "")).strip()
        if not remote_url:
            checks["checks"].append({"name": "remote_url", "ok": False, "error": "remoteUrl is required for selenium_remote."})
            return checks
        checks["checks"].append({"name": "remote_url", "ok": True, "remoteUrl": remote_url})
        checks["ok"] = True
        return checks
    checks["checks"].append({"name": "provider", "ok": False, "error": f"Unsupported provider: {provider}"})
    return checks


def browser_authenticate(args: dict[str, Any]) -> dict[str, Any]:
    profile = get_auth_profile(str(args["profileId"]), include_secret=True)
    if profile.get("type") != "browser_auth":
        raise McpError(-32602, f"Authentication profile is not a browser_auth profile: {profile['id']}")
    target = str(args.get("target") or profile["loginUrl"])
    host = scope.normalize_host(target)
    if host not in set(profile.get("scopes", [])):
        raise McpError(-32002, f"Authentication profile {profile['id']} is not scoped for target host: {host}")
    if bool(args.get("background", True)):
        if any(key in args for key in ("username", "password", "manualValues")):
            raise McpError(
                -32001,
                "Execute-time username, password, or manualValues overrides are not persisted to background job files. Store reusable credentials in the profile or run with background=false for one-time interactive values.",
            )
        return _start_background_browser_auth(args, profile, target, host)
    provider = str(args.get("provider") or profile.get("provider", "playwright")).strip().lower()
    existing = _reuse_existing_browser_session(profile, args, target, host, provider)
    if existing:
        return existing
    if provider == "playwright":
        result = _run_playwright_browser_auth(profile, args)
    elif provider == "selenium_remote":
        result = _run_selenium_browser_auth(profile, args)
    else:
        raise McpError(-32602, f"Unsupported browser auth provider: {provider}")
    credential = _save_session_credential(profile, result, args)
    validation = _validate_session_credential(credential, profile, args)
    evidence.log_event(
        "credentials.browser_authenticate",
        f"Browser-authenticated profile {profile['id']} and refreshed credential {credential['id']}.",
        {
            "profileId": profile["id"],
            "credentialId": credential["id"],
            "target": host,
            "loginHost": scope.normalize_host(profile["loginUrl"]),
            "provider": provider,
            "cookieNames": result.get("summary", {}).get("cookieNames", []),
            "storageKeys": result.get("summary", {}).get("storageKeys", []),
            "validation": validation,
        },
    )
    return {
        "authenticated": True,
        "profileId": profile["id"],
        "provider": provider,
        "credential": redact_credential(credential),
        "summary": result.get("summary", {}),
        "validation": validation,
        "finalUrl": result.get("finalUrl", ""),
    }


def _reuse_existing_browser_session(profile: dict[str, Any], args: dict[str, Any], target: str, host: str, provider: str) -> dict[str, Any] | None:
    if not bool(args.get("validateExistingSessionFirst", False)):
        return None
    try:
        credential = credential_for_target(str(profile["credentialId"]), target)
    except McpError:
        return None
    if credential.get("type") != "session":
        return None
    validation = _validate_session_credential(credential, profile, args)
    if not validation.get("ok"):
        return None
    evidence.log_event(
        "credentials.browser_authenticate",
        f"Validated existing browser session for profile {profile['id']} without launching a browser.",
        {
            "profileId": profile["id"],
            "credentialId": credential["id"],
            "target": host,
            "loginHost": scope.normalize_host(profile["loginUrl"]),
            "provider": provider,
            "validation": validation,
            "usedExistingSession": True,
            "browserLaunched": False,
        },
    )
    summary = dict(credential.get("sessionSummary", {}) if isinstance(credential.get("sessionSummary"), dict) else {})
    summary.update({"usedExistingSession": True, "browserLaunched": False})
    return {
        "authenticated": True,
        "profileId": profile["id"],
        "provider": provider,
        "credential": redact_credential(credential),
        "summary": summary,
        "validation": validation,
        "finalUrl": validation.get("url", ""),
        "usedExistingSession": True,
        "browserLaunched": False,
    }


def _start_background_browser_auth(args: dict[str, Any], profile: dict[str, Any], target: str, host: str) -> dict[str, Any]:
    from . import background_jobs, dumps, workspace

    workspace_id = str(args.get("workspaceId") or workspace.default_workspace_id())
    worker_args = _strip_worker_secrets(dict(args))
    worker_args["background"] = False
    profile_slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(profile.get("id") or "profile")).strip("-")[:48] or "profile"
    artifact_stem = f"browser-auth-{profile_slug}-{uuid4().hex[:8]}"
    args_path = workspace.target_output_path(workspace_id, host, "jobs", f"{artifact_stem}-args.json")
    result_path = workspace.target_output_path(workspace_id, host, "jobs", f"{artifact_stem}-result.json")
    state_path = workspace.target_output_path(workspace_id, host, "jobs", f"{artifact_stem}-state.json")
    _write_private_json(args_path, worker_args)
    _write_private_json(
        state_path,
        {
            "workspacesDir": str(workspace.WORKSPACES_DIR),
            "dumpDir": str(dumps.DUMP_DIR),
            "scopeFile": str(scope.SCOPE_FILE),
            "credentialsFile": str(CREDENTIALS_FILE),
            "evidenceDir": str(evidence.EVIDENCE_DIR),
            "evidenceLog": str(evidence.EVIDENCE_LOG),
            "orgsDir": str(evidence.ORGS_DIR),
        },
    )
    timeout_seconds = int(args.get("timeoutSeconds") or args.get("authTimeoutSeconds") or DEFAULT_AUTH_TIMEOUT_SECONDS)
    cmd = [
        synapse_python(),
        "-m",
        "synapse_mcp.core.job_worker",
        "--tool",
        "credentials.browser_authenticate",
        "--args",
        str(args_path),
        "--result",
        str(result_path),
        "--state",
        str(state_path),
    ]
    event_data = {
        "workspaceId": workspace_id,
        "target": target,
        "host": host,
        "profileId": profile["id"],
        "credentialId": profile["credentialId"],
        "provider": profile.get("provider", "playwright"),
        "manualCompletion": profile.get("manualCompletion", False),
        "artifactStem": artifact_stem,
        "approval": {
            "confirm": args.get("confirm") is True,
            "approvalId": args.get("approvalId", ""),
            "approvalReason": args.get("approvalReason", ""),
            "riskTier": args.get("riskTier", ""),
        },
    }
    job = background_jobs.start_command(
        cmd,
        timeout_seconds=timeout_seconds,
        event_type="credentials.browser_authenticate",
        summary=f"Browser authentication for profile {profile['id']} against {host}",
        display_cmd=cmd,
        event_data=event_data,
        tool="credentials.browser_authenticate",
        workspace_id=workspace_id,
        target=target,
        output_path=str(result_path),
        finalizer_name="worker.result",
        finalizer_data={"resultPath": str(result_path), "cleanupArgsPath": str(args_path)},
    )
    return {
        "target": target,
        "workspaceId": workspace_id,
        "background": True,
        "job": job,
        "status": "started",
        "instruction": f"Poll with jobs.status(jobId={job['jobId']})",
        "workerArgsPath": str(args_path),
        "workerStatePath": str(state_path),
        "resultPath": str(result_path),
        "artifactStem": artifact_stem,
        "timeoutSeconds": timeout_seconds,
    }


def _save_session_credential(profile: dict[str, Any], result: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    bundle = {
        "provider": result.get("provider", profile.get("provider", "browser")),
        "loginUrl": profile["loginUrl"],
        "finalUrl": result.get("finalUrl", ""),
        "cookies": result.get("cookies", []),
        "origins": result.get("origins", []),
        "tokens": result.get("tokens", {}),
        "headers": result.get("headers", {}),
        "capturedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    auth_key = str(profile.get("authorizationStorageKey", ""))
    if auth_key and isinstance(bundle["tokens"], dict) and bundle["tokens"].get(auth_key):
        bundle["authorization"] = {"scheme": profile.get("authorizationScheme", "Bearer"), "value": bundle["tokens"][auth_key]}
    if not bundle["cookies"] and not bundle["tokens"]:
        raise McpError(-32000, "Browser authentication completed but no cookies or configured token storage values were captured.")
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    credential = {
        "id": profile["credentialId"],
        "type": "session",
        "scopes": profile["scopes"],
        "label": profile.get("label") or f"Browser session from {profile['id']}",
        "secret": json.dumps(bundle, ensure_ascii=False, sort_keys=True),
        "authProfileId": profile["id"],
        "issuedAt": now,
        "lastAuthenticatedAt": now,
        "sessionSummary": result.get("summary", {}),
    }
    _upsert_credential(credential)
    return credential


def validate_session(args: dict[str, Any]) -> dict[str, Any]:
    credential = credential_for_target(str(args["credentialId"]), str(args["target"]))
    profile: dict[str, Any] = {}
    profile_id = str(credential.get("authProfileId", ""))
    if profile_id:
        try:
            profile = get_auth_profile(profile_id, include_secret=True)
        except McpError:
            profile = {}
    validation = _validate_session_credential(credential, profile, args)
    evidence.log_event(
        "credentials.validate_session",
        f"Validated credential {credential['id']} against {scope.normalize_host(str(args['target']))}.",
        {"credentialId": credential["id"], "target": args["target"], "validation": validation},
    )
    return {"credential": redact_credential(credential), "validation": validation}


def _validate_session_credential(credential: dict[str, Any], profile: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("protectedUrl") or profile.get("protectedUrl") or args.get("target") or profile.get("loginUrl") or "")
    if not target:
        return {"checked": False, "reason": "No validation target was supplied."}
    headers = headers_for_credential_target(credential, target)
    if not headers:
        return {"checked": False, "reason": "Credential did not resolve to headers for the validation target."}
    response = http_client.send(
        HttpRequest(url=target, method="GET", headers={"Accept": "text/html,application/json,*/*", **headers}),
        policy=HttpClientPolicy.from_args(
            {**args, "maxBodyBytes": int(args.get("maxBodyBytes", 80_000))},
            timeout_seconds=int(args.get("requestTimeout", DEFAULT_AUTH_REQUEST_TIMEOUT_SECONDS)),
        ),
    )
    if response.status is None:
        return {"checked": True, "ok": False, "error": response.error, "appliedSession": _session_header_summary(headers)}
    success_codes = set(profile.get("successStatusCodes", []) or args.get("successStatusCodes", [200, 204, 302, 303]))
    failure_pattern = str(profile.get("failurePattern", "") or args.get("failurePattern", ""))
    success_pattern = str(profile.get("successPattern", "") or args.get("successPattern", ""))
    ok = response.status in success_codes
    reason = ""
    if failure_pattern and re.search(failure_pattern, response.body, re.I):
        ok = False
        reason = "Validation response matched failurePattern."
    if success_pattern and not re.search(success_pattern, response.body, re.I):
        ok = False
        reason = "Validation response did not match successPattern."
    return {"checked": True, "ok": ok, "status": response.status, "url": response.url or target, "reason": reason, "appliedSession": _session_header_summary(headers)}


def _browser_pattern_failure_message(profile: dict[str, Any], pattern_name: str, final_url: str) -> str:
    url_suffix = f" at {final_url}" if final_url else ""
    return (
        f"Browser authentication failed configured {pattern_name} check for profile {profile.get('id', '')}{url_suffix}. "
        "An existing scoped session may still be valid; run credentials.validate_session or retry "
        "credentials.browser_authenticate with validateExistingSessionFirst=true to distinguish profile drift from session failure."
    )


def _session_header_summary(headers: dict[str, str]) -> dict[str, Any]:
    cookie_names = []
    cookie_header = headers.get("Cookie", "")
    for part in cookie_header.split(";"):
        name = part.split("=", 1)[0].strip()
        if name:
            cookie_names.append(name)
    return {
        "headerNames": sorted(name for name in headers if name.lower() != "cookie"),
        "cookieNames": sorted(cookie_names),
        "hasCookies": bool(cookie_names),
        "hasAuthorization": "Authorization" in headers,
    }


def _run_playwright_browser_auth(profile: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise McpError(
            -32000,
            "Playwright is not available. Install optional browser support with: python3 -m pip install '.[browser]' && python3 -m playwright install chromium",
        ) from exc
    provider = "playwright"
    browser_name = str(args.get("browser") or profile.get("browser", "chromium")).lower()
    timeout_ms = int(args.get("authTimeoutSeconds") or args.get("timeoutSeconds") or DEFAULT_AUTH_TIMEOUT_SECONDS) * 1000
    headless = bool(args.get("headless", profile.get("headless", True)))
    proxy_url = args.get("proxyUrl") or args.get("proxy")
    try:
        with sync_playwright() as pw:
            engine = getattr(pw, browser_name)
            launch_args: dict[str, Any] = {"headless": headless}
            if proxy_url:
                launch_args["proxy"] = {"server": str(proxy_url)}
            browser = engine.launch(**launch_args)
            context = browser.new_context(ignore_https_errors=not bool(args.get("verifyTls", True)))
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            _execute_playwright_steps(page, profile, args)
            _wait_for_browser_success_playwright(page, profile, timeout_ms)
            state = context.storage_state()
            browser_headers = _playwright_browser_headers(page, profile)
            body_text = ""
            try:
                body_text = page.locator("body").inner_text(timeout=2000)
            except Exception:
                body_text = ""
            final_url = page.url
            browser.close()
    except PlaywrightTimeoutError as exc:
        raise McpError(-32000, f"Browser authentication timed out: {exc}") from exc
    except Exception as exc:
        raise McpError(-32000, f"Browser authentication failed: {type(exc).__name__}: {exc}") from exc
    if profile.get("failurePattern") and re.search(str(profile["failurePattern"]), body_text, re.I):
        raise McpError(-32000, _browser_pattern_failure_message(profile, "failurePattern", final_url))
    if profile.get("successPattern") and not re.search(str(profile["successPattern"]), body_text, re.I):
        raise McpError(-32000, _browser_pattern_failure_message(profile, "successPattern", final_url))
    return _browser_result_from_storage_state(provider, profile, state, final_url, browser_headers)


def _execute_playwright_steps(page: Any, profile: dict[str, Any], args: dict[str, Any]) -> None:
    steps = profile.get("steps") or []
    if not steps:
        page.goto(str(profile["loginUrl"]), wait_until="domcontentloaded")
        _playwright_fill_first(page, profile.get("usernameSelectors", DEFAULT_USERNAME_SELECTORS), str(profile.get("username", "")))
        _playwright_fill_first(page, profile.get("passwordSelectors", DEFAULT_PASSWORD_SELECTORS), str(profile.get("password", "")))
        if _playwright_click_first(page, profile.get("submitSelectors", DEFAULT_SUBMIT_SELECTORS)):
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
        return
    for step in steps:
        action = step["action"]
        timeout = int(step.get("timeoutMillis") or 0) or None
        if action == "goto":
            page.goto(_resolve_browser_value(str(step.get("url") or profile["loginUrl"]), profile, args), wait_until="domcontentloaded", timeout=timeout)
        elif action == "fill":
            page.fill(str(step["selector"]), _resolve_browser_value(str(step.get("value", "")), profile, args), timeout=timeout)
        elif action == "click":
            page.click(str(step["selector"]), timeout=timeout)
        elif action == "press":
            page.press(str(step["selector"]), _resolve_browser_value(str(step.get("key", "Enter")), profile, args), timeout=timeout)
        elif action == "select":
            page.select_option(str(step["selector"]), _resolve_browser_value(str(step.get("value", "")), profile, args), timeout=timeout)
        elif action == "check":
            page.check(str(step["selector"]), timeout=timeout)
        elif action == "uncheck":
            page.uncheck(str(step["selector"]), timeout=timeout)
        elif action == "wait_for_url":
            page.wait_for_url(_resolve_browser_value(str(step.get("url", "**")), profile, args), timeout=timeout)
        elif action == "wait_for_selector":
            page.wait_for_selector(str(step["selector"]), timeout=timeout)
        elif action == "wait_for_load_state":
            page.wait_for_load_state(str(step.get("state", "networkidle")), timeout=timeout)


def _playwright_fill_first(page: Any, selectors: list[str], value: str) -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible(timeout=1000):
                locator.fill(value)
                return True
        except Exception:
            continue
    return False


def _playwright_click_first(page: Any, selectors: list[str]) -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible(timeout=1000):
                locator.click()
                return True
        except Exception:
            continue
    return False


def _wait_for_browser_success_playwright(page: Any, profile: dict[str, Any], timeout_ms: int) -> None:
    if profile.get("manualCompletion"):
        deadline = time.time() + (timeout_ms / 1000)
        while time.time() < deadline:
            if _playwright_success_met(page, profile):
                return
            time.sleep(1)
        raise McpError(-32000, "Browser-assisted authentication timed out before a success condition was met.")
    if profile.get("successUrlPattern"):
        page.wait_for_url(re.compile(str(profile["successUrlPattern"])), timeout=timeout_ms)
    if profile.get("successSelector"):
        page.wait_for_selector(str(profile["successSelector"]), timeout=timeout_ms)


def _playwright_success_met(page: Any, profile: dict[str, Any]) -> bool:
    if profile.get("successUrlPattern") and re.search(str(profile["successUrlPattern"]), page.url):
        return True
    if profile.get("successSelector"):
        try:
            return page.locator(str(profile["successSelector"])).first.is_visible(timeout=1000)
        except Exception:
            return False
    return True


def _playwright_browser_headers(page: Any, profile: dict[str, Any]) -> dict[str, str]:
    if not profile.get("captureBrowserHeaders", True):
        return {}
    headers: dict[str, str] = {}
    try:
        user_agent = str(page.evaluate("() => navigator.userAgent") or "").strip()
        if user_agent:
            headers["User-Agent"] = user_agent
    except Exception:
        pass
    try:
        language = str(page.evaluate("() => navigator.language || (navigator.languages && navigator.languages[0]) || ''") or "").strip()
        if language:
            headers["Accept-Language"] = language
    except Exception:
        pass
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7"
    return _safe_browser_headers(headers)


def _run_selenium_browser_auth(profile: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    try:
        from selenium import webdriver  # type: ignore
        from selenium.webdriver.common.by import By  # type: ignore
        from selenium.webdriver.common.keys import Keys  # type: ignore
        from selenium.webdriver.support import expected_conditions as EC  # type: ignore
        from selenium.webdriver.support.ui import WebDriverWait  # type: ignore
    except Exception as exc:
        raise McpError(-32000, "Selenium is not available. Install optional browser support with: python3 -m pip install '.[browser]'") from exc
    remote_url = str(args.get("remoteUrl") or profile.get("remoteUrl", "")).strip()
    if not remote_url:
        raise McpError(-32602, "remoteUrl is required for selenium_remote browser authentication.")
    timeout = int(args.get("authTimeoutSeconds") or args.get("timeoutSeconds") or DEFAULT_AUTH_TIMEOUT_SECONDS)
    browser_name = str(args.get("browser") or profile.get("browser", "chromium")).lower()
    options = webdriver.ChromeOptions() if browser_name == "chromium" else webdriver.FirefoxOptions()
    if bool(args.get("headless", profile.get("headless", True))):
        options.add_argument("--headless=new")
    driver = webdriver.Remote(command_executor=remote_url, options=options)
    try:
        driver.set_page_load_timeout(timeout)
        wait = WebDriverWait(driver, timeout)
        steps = profile.get("steps") or []
        if not steps:
            driver.get(str(profile["loginUrl"]))
            _selenium_fill_first(driver, By, profile.get("usernameSelectors", DEFAULT_USERNAME_SELECTORS), str(profile.get("username", "")))
            _selenium_fill_first(driver, By, profile.get("passwordSelectors", DEFAULT_PASSWORD_SELECTORS), str(profile.get("password", "")))
            if not _selenium_click_first(driver, By, profile.get("submitSelectors", DEFAULT_SUBMIT_SELECTORS)):
                driver.switch_to.active_element.send_keys(Keys.ENTER)
        else:
            for step in steps:
                _execute_selenium_step(driver, wait, By, Keys, EC, profile, args, step)
        if profile.get("manualCompletion"):
            deadline = time.time() + timeout
            while time.time() < deadline:
                if _selenium_success_met(driver, By, profile):
                    break
                time.sleep(1)
            else:
                raise McpError(-32000, "Browser-assisted authentication timed out before a success condition was met.")
        elif profile.get("successUrlPattern"):
            wait.until(lambda drv: re.search(str(profile["successUrlPattern"]), drv.current_url))
        if profile.get("successSelector"):
            wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, str(profile["successSelector"]))))
        body_text = driver.find_element(By.TAG_NAME, "body").text
        final_url = driver.current_url
        cookies = driver.get_cookies()
        origins = _selenium_storage(driver, profile)
        browser_headers = _selenium_browser_headers(driver, profile)
    finally:
        driver.quit()
    if profile.get("failurePattern") and re.search(str(profile["failurePattern"]), body_text, re.I):
        raise McpError(-32000, _browser_pattern_failure_message(profile, "failurePattern", final_url))
    if profile.get("successPattern") and not re.search(str(profile["successPattern"]), body_text, re.I):
        raise McpError(-32000, _browser_pattern_failure_message(profile, "successPattern", final_url))
    return _browser_result_from_storage_state("selenium_remote", profile, {"cookies": cookies, "origins": origins}, final_url, browser_headers)


def _execute_selenium_step(driver: Any, wait: Any, By: Any, Keys: Any, EC: Any, profile: dict[str, Any], args: dict[str, Any], step: dict[str, Any]) -> None:
    action = step["action"]
    if action == "goto":
        driver.get(_resolve_browser_value(str(step.get("url") or profile["loginUrl"]), profile, args))
    elif action == "fill":
        element = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, str(step["selector"]))))
        element.clear()
        element.send_keys(_resolve_browser_value(str(step.get("value", "")), profile, args))
    elif action == "click":
        wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, str(step["selector"])))).click()
    elif action == "press":
        key = _resolve_browser_value(str(step.get("key", "Enter")), profile, args)
        element = driver.find_element(By.CSS_SELECTOR, str(step.get("selector", "body")))
        element.send_keys(getattr(Keys, key.upper(), key))
    elif action == "select":
        from selenium.webdriver.support.ui import Select  # type: ignore

        Select(driver.find_element(By.CSS_SELECTOR, str(step["selector"]))).select_by_value(_resolve_browser_value(str(step.get("value", "")), profile, args))
    elif action == "check":
        element = driver.find_element(By.CSS_SELECTOR, str(step["selector"]))
        if not element.is_selected():
            element.click()
    elif action == "uncheck":
        element = driver.find_element(By.CSS_SELECTOR, str(step["selector"]))
        if element.is_selected():
            element.click()
    elif action == "wait_for_url":
        pattern = _resolve_browser_value(str(step.get("url", ".*")), profile, args).replace("**", ".*")
        wait.until(lambda drv: re.search(pattern, drv.current_url))
    elif action == "wait_for_selector":
        wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, str(step["selector"]))))
    elif action == "wait_for_load_state":
        wait.until(lambda drv: drv.execute_script("return document.readyState") == "complete")


def _selenium_fill_first(driver: Any, By: Any, selectors: list[str], value: str) -> bool:
    for selector in selectors:
        try:
            element = driver.find_element(By.CSS_SELECTOR, selector)
            if element.is_displayed():
                element.clear()
                element.send_keys(value)
                return True
        except Exception:
            continue
    return False


def _selenium_click_first(driver: Any, By: Any, selectors: list[str]) -> bool:
    for selector in selectors:
        try:
            element = driver.find_element(By.CSS_SELECTOR, selector)
            if element.is_displayed() and element.is_enabled():
                element.click()
                return True
        except Exception:
            continue
    return False


def _selenium_success_met(driver: Any, By: Any, profile: dict[str, Any]) -> bool:
    if profile.get("successUrlPattern") and re.search(str(profile["successUrlPattern"]), driver.current_url):
        return True
    if profile.get("successSelector"):
        try:
            return driver.find_element(By.CSS_SELECTOR, str(profile["successSelector"])).is_displayed()
        except Exception:
            return False
    return True


def _selenium_storage(driver: Any, profile: dict[str, Any]) -> list[dict[str, Any]]:
    if not profile.get("captureStorage", True):
        return []
    origin = "{uri.scheme}://{uri.netloc}".format(uri=urlsplit(str(driver.current_url)))
    local_storage = driver.execute_script("return Object.entries(window.localStorage || {}).map(([name,value]) => ({name,value}))")
    session_storage = driver.execute_script("return Object.entries(window.sessionStorage || {}).map(([name,value]) => ({name,value}))")
    return [{"origin": origin, "localStorage": local_storage or [], "sessionStorage": session_storage or []}]


def _selenium_browser_headers(driver: Any, profile: dict[str, Any]) -> dict[str, str]:
    if not profile.get("captureBrowserHeaders", True):
        return {}
    headers: dict[str, str] = {}
    try:
        user_agent = str(driver.execute_script("return navigator.userAgent") or "").strip()
        if user_agent:
            headers["User-Agent"] = user_agent
    except Exception:
        pass
    try:
        language = str(driver.execute_script("return navigator.language || (navigator.languages && navigator.languages[0]) || ''") or "").strip()
        if language:
            headers["Accept-Language"] = language
    except Exception:
        pass
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7"
    return _safe_browser_headers(headers)


def _safe_browser_headers(headers: dict[str, str]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for name, value in headers.items():
        name_text = str(name).strip()
        value_text = str(value).strip()
        if name_text not in SESSION_BROWSER_HEADER_ALLOWLIST:
            continue
        if not value_text or "\r" in value_text or "\n" in value_text:
            continue
        safe[name_text] = value_text
    return safe


def _browser_result_from_storage_state(provider: str, profile: dict[str, Any], state: dict[str, Any], final_url: str, browser_headers: dict[str, str] | None = None) -> dict[str, Any]:
    allowed_cookies = set(profile.get("cookieNames", []))
    cookies = []
    for cookie in state.get("cookies", []) if isinstance(state.get("cookies"), list) else []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name", ""))
        if allowed_cookies and name not in allowed_cookies:
            continue
        cookies.append(
            {
                "name": name,
                "value": str(cookie.get("value", "")),
                "domain": str(cookie.get("domain", "")),
                "path": str(cookie.get("path", "/") or "/"),
                "expires": cookie.get("expires", -1),
                "httpOnly": bool(cookie.get("httpOnly", False)),
                "secure": bool(cookie.get("secure", False)),
                "sameSite": str(cookie.get("sameSite", "")),
            }
        )
    origins = state.get("origins", []) if profile.get("captureStorage", True) else []
    tokens = _extract_storage_tokens(origins, profile.get("tokenStorageKeys", []))
    return {
        "provider": provider,
        "finalUrl": final_url,
        "cookies": cookies,
        "origins": origins if profile.get("captureStorage", True) else [],
        "tokens": tokens,
        "headers": _safe_browser_headers(browser_headers or {}),
        "summary": {
            "cookieNames": sorted({cookie["name"] for cookie in cookies}),
            "storageKeys": _storage_key_names(origins) if profile.get("captureStorage", True) else [],
            "tokenStorageKeys": sorted(tokens),
            "browserHeaderNames": sorted(_safe_browser_headers(browser_headers or {})),
            "finalHost": scope.normalize_host(final_url),
        },
    }


def _extract_storage_tokens(origins: Any, keys: list[str]) -> dict[str, str]:
    wanted = set(keys)
    if not wanted or not isinstance(origins, list):
        return {}
    tokens: dict[str, str] = {}
    for origin in origins:
        if not isinstance(origin, dict):
            continue
        for storage_name in ("localStorage", "sessionStorage"):
            entries = origin.get(storage_name, [])
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict) and entry.get("name") in wanted:
                    tokens[str(entry["name"])] = str(entry.get("value", ""))
    return tokens


def _storage_key_names(origins: Any) -> list[str]:
    names: set[str] = set()
    if not isinstance(origins, list):
        return []
    for origin in origins:
        if not isinstance(origin, dict):
            continue
        for storage_name in ("localStorage", "sessionStorage"):
            entries = origin.get(storage_name, [])
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict) and entry.get("name"):
                    names.add(str(entry["name"]))
    return sorted(names)


def _resolve_browser_value(value: str, profile: dict[str, Any], args: dict[str, Any]) -> str:
    replacements = {
        "{{username}}": str(args.get("username") or profile.get("username", "")),
        "{{password}}": str(args.get("password") or profile.get("password", "")),
    }
    manual_values = args.get("manualValues", {})
    if isinstance(manual_values, dict):
        for key, item in manual_values.items():
            replacements[f"{{{{{key}}}}}"] = str(item)
    resolved = value
    for marker, replacement in replacements.items():
        resolved = resolved.replace(marker, replacement)
    return resolved
