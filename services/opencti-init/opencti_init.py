import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx

logging.basicConfig(level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")
logger = logging.getLogger(__name__)
FALLBACK_TOKEN = ""


@dataclass
class MutationInfo:
    name: str
    input_type: str | None


def _is_auth_required(exc: Exception) -> bool:
    if isinstance(exc, RuntimeError) and exc.args:
        errors = exc.args[0]
        if isinstance(errors, list):
            for error in errors:
                code = error.get("extensions", {}).get("code")
                message = (error.get("message") or "").lower()
                if code == "AUTH_REQUIRED":
                    return True
                if "cant identify" in message or "can not identify" in message:
                    return True
    msg = str(exc).lower()
    return "auth_required" in msg or "cant identify" in msg or "can not identify" in msg


def _is_schema_error(exc: Exception) -> bool:
    msg = str(exc)
    return "Unknown type" in msg or "Cannot query field" in msg


def _post(url: str, token: str, query: str, variables: dict[str, Any]) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = {"query": query, "variables": variables}
    with httpx.Client(timeout=30) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()
        if "errors" in body:
            exc = RuntimeError(body["errors"])
            if FALLBACK_TOKEN and FALLBACK_TOKEN != token and _is_auth_required(exc):
                return _post(url, FALLBACK_TOKEN, query, variables)
            raise exc
        return body.get("data", {})


def _get_mutations(url: str, token: str) -> list[MutationInfo]:
    query = """
    query Schema {
      __schema {
        mutationType {
          fields {
            name
            args {
              name
              type { kind name ofType { kind name ofType { kind name } } }
            }
          }
        }
      }
    }
    """
    data = _post(url, token, query, {})
    fields = data.get("__schema", {}).get("mutationType", {}).get("fields", [])
    mutations: list[MutationInfo] = []
    for field in fields:
        input_type = None
        for arg in field.get("args", []):
            if arg.get("name") == "input":
                t = arg.get("type")
                while t and t.get("kind") == "NON_NULL":
                    t = t.get("ofType")
                if t:
                    input_type = t.get("name")
        mutations.append(MutationInfo(name=field.get("name"), input_type=input_type))
    return mutations


def _get_input_fields(url: str, token: str, type_name: str) -> list[tuple[str, bool]]:
    query = """
    query InputFields($name: String!) {
      __type(name: $name) {
        inputFields {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
      }
    }
    """
    data = _post(url, token, query, {"name": type_name})
    fields = data.get("__type", {}).get("inputFields", [])
    parsed = []
    for field in fields:
        required = False
        t = field.get("type")
        if t and t.get("kind") == "NON_NULL":
            required = True
        parsed.append((field.get("name"), required))
    return parsed


def _create_service_account_without_introspection(
    url: str, token: str, name: str, api_token: str
) -> bool:
    candidates = [
        ("serviceAccountAdd", "ServiceAccountAddInput"),
        ("serviceAccountCreate", "ServiceAccountCreateInput"),
        ("userServiceAccountAdd", "UserServiceAccountAddInput"),
        ("userServiceAccountCreate", "UserServiceAccountCreateInput"),
    ]
    payload = {"name": name, "description": f"Service account for {name}", "token": api_token}
    for mutation_name, input_type in candidates:
        query = f"""
        mutation Create($input: {input_type}!) {{
          {mutation_name}(input: $input) {{ id name }}
        }}
        """
        try:
            _post(url, token, query, {"input": payload})
            logger.info("service_account_created name=%s", name)
            return True
        except Exception as exc:
            if _is_schema_error(exc):
                logger.warning("service_account_api_not_supported")
                return False
            logger.warning("service_account_create_failed name=%s error=%s", name, exc)
    return False


def _create_service_account(url: str, token: str, name: str, api_token: str) -> bool:
    candidates = [
        "serviceAccountAdd",
        "serviceAccountCreate",
        "userServiceAccountAdd",
        "userServiceAccountCreate",
    ]
    try:
        mutations = _get_mutations(url, token)
    except Exception as exc:
        msg = str(exc)
        if "introspection" in msg.lower():
            return _create_service_account_without_introspection(url, token, name, api_token)
        raise
    mutation_map = {m.name: m for m in mutations}

    for candidate in candidates:
        if candidate not in mutation_map:
            continue
        input_type = mutation_map[candidate].input_type
        if not input_type:
            continue
        fields = _get_input_fields(url, token, input_type)
        payload: dict[str, Any] = {}
        unsupported_required = []
        for field_name, required in fields:
            if field_name in {"name", "title"}:
                payload[field_name] = name
            elif field_name in {"description"}:
                payload[field_name] = f"Service account for {name}"
            elif field_name in {"token", "apiToken", "api_token"}:
                payload[field_name] = api_token
            elif required:
                unsupported_required.append(field_name)
        if unsupported_required:
            continue
        query = f"""
        mutation Create($input: {input_type}!) {{
          {candidate}(input: $input) {{ id name }}
        }}
        """
        try:
            _post(url, token, query, {"input": payload})
            logger.info("service_account_created name=%s", name)
            return True
        except Exception as exc:
            logger.warning("service_account_create_failed name=%s error=%s", name, exc)
            return False
    return False


def _existing_service_account(url: str, token: str, name: str) -> bool:
    query = """
    query Users($search: String) {
      users(search: $search, first: 5) {
        edges { node { name } }
      }
    }
    """
    try:
        data = _post(url, token, query, {"search": name})
    except Exception:
        return False
    edges = data.get("users", {}).get("edges", [])
    for edge in edges:
        node = edge.get("node", {})
        if node.get("name") == name:
            return True
    return False


def _get_roles(url: str, token: str) -> list[dict[str, Any]]:
    query = """
    query Roles($search: String) {
      roles(search: $search, first: 50) {
        edges { node { id name } }
      }
    }
    """
    try:
        data = _post(url, token, query, {"search": ""})
    except Exception as exc:
        logger.warning("role_lookup_failed error=%s", exc)
        return []
    return [edge.get("node", {}) for edge in data.get("roles", {}).get("edges", [])]


def _find_role_id(roles: list[dict[str, Any]], name: str) -> str | None:
    for role in roles:
        if role.get("name") == name:
            return role.get("id")
    return None


def _create_user_without_introspection(
    url: str, token: str, name: str, email: str, password: str, role_id: str | None
) -> bool:
    candidates = [("userAdd", "UserAddInput"), ("userCreate", "UserCreateInput")]
    payload: dict[str, Any] = {"name": name, "user_email": email, "password": password}
    if role_id:
        payload["roles"] = [role_id]
    for mutation_name, input_type in candidates:
        query = f"""
        mutation Create($input: {input_type}!) {{
          {mutation_name}(input: $input) {{ id name }}
        }}
        """
        try:
            _post(url, token, query, {"input": payload})
            logger.info("user_created email=%s", email)
            return True
        except Exception as exc:
            if "Field \"user_email\" is not defined" in str(exc):
                payload["email"] = payload.pop("user_email")
                continue
            logger.warning("user_create_failed email=%s error=%s", email, exc)
    return False


def _create_user(url: str, token: str, name: str, email: str, password: str, role_id: str | None) -> bool:
    candidates = ["userAdd", "userCreate"]
    try:
        mutations = _get_mutations(url, token)
    except Exception as exc:
        msg = str(exc)
        if "introspection" in msg.lower():
            return _create_user_without_introspection(url, token, name, email, password, role_id)
        raise
    mutation_map = {m.name: m for m in mutations}
    for candidate in candidates:
        if candidate not in mutation_map:
            continue
        input_type = mutation_map[candidate].input_type
        if not input_type:
            continue
        fields = _get_input_fields(url, token, input_type)
        payload: dict[str, Any] = {}
        unsupported_required = []
        for field_name, required in fields:
            if field_name in {"name", "display_name"}:
                payload[field_name] = name
            elif field_name in {"email", "user_email"}:
                payload[field_name] = email
            elif field_name in {"password"}:
                payload[field_name] = password
            elif field_name in {"roles", "role"} and role_id:
                payload[field_name] = [role_id] if field_name == "roles" else role_id
            elif required:
                unsupported_required.append(field_name)
        if unsupported_required:
            continue
        query = f"""
        mutation Create($input: {input_type}!) {{
          {candidate}(input: $input) {{ id name }}
        }}
        """
        try:
            _post(url, token, query, {"input": payload})
            logger.info("user_created email=%s", email)
            return True
        except Exception as exc:
            logger.warning("user_create_failed email=%s error=%s", email, exc)
            return False
    return False


def _resolve_admin_token(admin_token: str, app_admin_token: str) -> str:
    if app_admin_token:
        if admin_token and admin_token != app_admin_token:
            logger.warning("admin_token_mismatch_using_app_admin")
        return app_admin_token
    if admin_token:
        return admin_token
    return ""


def main() -> None:
    base_url = os.getenv("OPENCTI_URL", "http://opencti:8080").rstrip("/")
    admin_token = os.getenv("OPENCTI_ADMIN_TOKEN", "")
    app_admin_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN", "")
    if not admin_token and not app_admin_token:
        logger.error("missing OPENCTI_ADMIN_TOKEN")
        return
    url = f"{base_url}/graphql"
    global FALLBACK_TOKEN
    FALLBACK_TOKEN = app_admin_token
    admin_token = _resolve_admin_token(admin_token, app_admin_token)

    accounts = {
        "Miniflux Connector": os.getenv("OPENCTI_MINIFLUX_TOKEN", ""),
        "Readwise Connector": os.getenv("OPENCTI_READWISE_TOKEN", ""),
        "Zotero Connector": os.getenv("OPENCTI_ZOTERO_TOKEN", ""),
    }

    if os.getenv("OPENCTI_INIT_SERVICE_ACCOUNTS", "").lower() == "true":
        for name, token in accounts.items():
            if not token:
                logger.warning("missing_token name=%s", name)
                continue
            if _existing_service_account(url, admin_token, name):
                logger.info("service_account_exists name=%s", name)
                continue
            _create_service_account(url, admin_token, name, token)
    else:
        logger.info("service_account_init_disabled")

    user_email = os.getenv("OPENCTI_USER_EMAIL", "")
    user_password = os.getenv("OPENCTI_USER_PASSWORD", "")
    user_name = os.getenv("OPENCTI_USER_NAME") or user_email
    user_role = os.getenv("OPENCTI_USER_ROLE", "Analyst")
    if user_email and user_password:
        if _existing_service_account(url, admin_token, user_email):
            logger.info("user_exists email=%s", user_email)
        else:
            roles = _get_roles(url, admin_token)
            role_id = _find_role_id(roles, user_role)
            _create_user(url, admin_token, user_name, user_email, user_password, role_id)


if __name__ == "__main__":
    main()
