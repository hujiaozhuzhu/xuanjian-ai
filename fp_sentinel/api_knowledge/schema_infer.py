"""OpenAPI 3.0 schema inference engine.

Infers request/response schemas from HTTP traffic samples (HAR entries, captured
requests). Supports nested dict/list, union types via oneOf, and common format
detection (email, uuid, date-time, uri).

Sensitive field names (password, secret, token, api_key, auth, cookie, credit,
session, phone, id_card) are annotated with ``x-sensitive: true``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


# Common string format detection patterns
_FORMAT_PATTERNS: List[tuple[str, str]] = [
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "uuid"),
    (re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"), "email"),
    (re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"), "date-time"),
    (re.compile(r"^https?://"), "uri"),
    (re.compile(r"^\d{4}-\d{2}-\d{2}$"), "date"),
]

# Sensitive field name patterns → annotated with x-sensitive=true
_SENSITIVE_FIELDS: list[str] = [
    "password", "secret", "token", "api_key", "auth", "cookie",
    "credit", "session", "phone", "id_card",
]


def _detect_format(value: str) -> Optional[str]:
    """Detect OpenAPI format for a string value."""
    return next((fmt for pat, fmt in _FORMAT_PATTERNS if pat.match(value)), None)


def _is_sensitive_field(name: str) -> bool:
    """Check if a field name matches sensitive patterns."""
    lowered = name.lower()
    for pattern in _SENSITIVE_FIELDS:
        if pattern in lowered:
            return True
    return False


def _annotate_sensitive(schema: dict, name: str = "") -> dict:
    """Walk a schema dict and add x-sensitive=true to sensitive fields."""
    if not isinstance(schema, dict):
        return schema
    result = dict(schema)
    if name and _is_sensitive_field(name):
        result["x-sensitive"] = True
    if "properties" in result and isinstance(result["properties"], dict):
        result["properties"] = {
            k: _annotate_sensitive(v, name=k)
            for k, v in result["properties"].items()
        }
    if "items" in result and isinstance(result["items"], dict):
        result["items"] = _annotate_sensitive(result["items"], name=name)
    if "oneOf" in result and isinstance(result["oneOf"], list):
        result["oneOf"] = [_annotate_sensitive(s, name=name) for s in result["oneOf"]]
    return result


class SchemaInferer:
    """Infer OpenAPI 3.0 schemas from request/response samples."""

    def infer_from_samples(
        self,
        method: str,
        url: str,
        request_samples: Optional[List[dict]] = None,
        response_samples: Optional[List[dict]] = None,
    ) -> dict:
        """Generate an OpenAPI paths fragment from traffic samples.

        Returns:
            dict: ``{"paths": {url: {method: {"parameters": [...], "requestBody": {...}, "responses": {...}}}}}``
        """
        path, path_params = self.extract_path_params(
            url, [url] if request_samples is None else [s.get("url", url) for s in request_samples]
        )
        parameters: list[dict] = path_params
        request_body: dict = {}
        responses: dict = {}

        if request_samples:
            body_samples: list[Any] = []
            query_samples: list[dict] = []
            for s in request_samples:
                if not isinstance(s, dict):
                    continue
                b = s.get("body")
                if b is not None:
                    body_samples.append(b)
                q = s.get("query", {})
                if isinstance(q, dict) and q:
                    query_samples.append(q)
            if body_samples:
                merged = self._sample_schema_merges(
                    [self.infer_schema([b]) for b in body_samples]
                )
                request_body = {"content": {"application/json": {"schema": merged}}}
            if query_samples:
                merged_q = self._sample_schema_merges(
                    [self.infer_schema([q]) for q in query_samples]
                )
                if "properties" in (isinstance(merged_q, dict) and merged_q or {}):
                    for pname, pschema in merged_q.get("properties", {}).items():
                        parameters.append(
                            {"name": pname, "in": "query", "schema": pschema}
                        )

        if response_samples:
            responses = self.infer_status_codes(response_samples)

        # Assemble OpenAPI operation
        operation: dict = {}
        if parameters:
            operation["parameters"] = parameters
        if request_body:
            operation["requestBody"] = request_body
        if responses:
            operation["responses"] = responses
        if not operation:
            operation["responses"] = {"200": {"description": ""}}

        return {"paths": {path: {method.lower(): operation}}}

    def infer_schema(self, samples: list[Any]) -> dict:
        """Infer JSON Schema (OpenAPI format) from a list of value samples.

        Types: int→integer, float→number, bool→boolean, str→string (with format
        detection for email/uuid/date-time/uri), list→array, dict→object.
        Mixed types use oneOf. Required fields are inferred when a key appears
        in >80% of samples (requires >=3 samples).
        """
        if not samples:
            return {"type": "object"}
        schemas = [self._python_type_to_schema(s) for s in samples]
        merged = self._sample_schema_merges(schemas)
        return _annotate_sensitive(merged)

    def _python_type_to_schema(self, value: Any) -> dict:
        """Map a single Python value to an OpenAPI schema fragment."""
        if value is None:
            return {"type": "null"}
        if isinstance(value, bool):
            return {"type": "boolean"}
        if isinstance(value, int):
            return {"type": "integer"}
        if isinstance(value, float):
            return {"type": "number"}
        if isinstance(value, str):
            fmt = _detect_format(value)
            return {"type": "string", "format": fmt} if fmt else {"type": "string"}
        if isinstance(value, list):
            if value:
                item_schemas = [self._python_type_to_schema(v) for v in value]
                merged = self._sample_schema_merges(item_schemas)
                return {"type": "array", "items": merged}
            return {"type": "array", "items": {"type": "string"}}
        if isinstance(value, dict):
            props: dict[str, dict] = {}
            for k, v in value.items():
                props[k] = self._python_type_to_schema(v)
            return {"type": "object", "properties": props}
        return {"type": "string"}

    def _sample_schema_merges(self, schemas: list[dict]) -> dict:
        """Merge multiple inferred schemas.

        - Same-type dicts: union of keys, required = keys present in >80% of samples.
        - Same-type arrays: merge item schemas.
        - Mixed types: use oneOf.
        """
        if not schemas:
            return {"type": "object"}
        if len(schemas) == 1:
            return schemas[0]

        by_type: dict[str, list[dict]] = {}
        for s in schemas:
            t = s.get("type", "object")
            by_type.setdefault(t, []).append(s)

        if len(by_type) > 1:
            unique: list[dict] = []
            for s in schemas:
                if s not in unique:
                    unique.append(s)
            if len(unique) == 1:
                return unique[0]
            return {"oneOf": unique}

        t, group = next(iter(by_type.items()))
        if t == "object":
            return self._merge_object_schemas(group)
        if t == "array":
            all_items: list[dict] = []
            for s in group:
                items = s.get("items", {})
                if items:
                    all_items.append(items)
            merged_items = self._sample_schema_merges(all_items) if all_items else {"type": "string"}
            return {"type": "array", "items": merged_items}

        return schemas[0]

    def _merge_object_schemas(self, group: list[dict]) -> dict:
        """Merge a group of object-type schemas."""
        all_keys: dict[str, int] = {}
        prop_schemes: dict[str, list[dict]] = {}
        for s in group:
            props = s.get("properties", {})
            for k, v in props.items():
                all_keys[k] = all_keys.get(k, 0) + 1
                prop_schemes.setdefault(k, []).append(v)
        threshold = 0.8 * len(group)
        required = [k for k, cnt in all_keys.items() if cnt > threshold]
        merged_props = {
            k: self._sample_schema_merges(v) for k, v in prop_schemes.items()
        }
        result: dict = {"type": "object", "properties": merged_props}
        if required:
            result["required"] = required
        return result

    def merge_schemas(self, schemas: list[dict]) -> dict:
        """Public merge method: diverse-sample merge.

        Rules:
        - required: intersection of required sets (keys present in >80% of samples)
        - type: oneOf if types disagree, else union
        - properties: recursively merge per-key
        """
        return self._sample_schema_merges(schemas)

    def extract_path_params(
        self, path_template: str, sample_paths: Optional[List[str]] = None
    ) -> tuple[str, list[dict]]:
        """Detect templatized path parameters from sample URLs.

        Given ``/api/user/{id}`` and samples like ``/api/user/1``, ``/api/user/abc``,
        returns the template and a parameter list with inferred types.

        Args:
            path_template: URL template (or concrete path if no template yet).
            sample_paths: Observed concrete paths for type inference.

        Returns:
            tuple of (templatized_path, parameter_list)
        """
        if not sample_paths or len(sample_paths) < 2 or not path_template:
            return path_template, []
        parts_all: list[list[str]] = []
        for s in sample_paths:
            if not s:
                continue
            clean = s.split("?")[0]
            parts_all.append(clean.split("/"))
        if len(parts_all) < 2:
            return path_template, []
        depth = min(len(p) for p in parts_all)
        varying_indices: list[int] = []
        for i in range(depth):
            values = {p[i] for p in parts_all}
            if len(values) > 1:
                varying_indices.append(i)
        if not varying_indices:
            return path_template, []
        orig_parts = path_template.split("/")
        parameters: list[dict] = []
        for idx in varying_indices:
            if idx >= len(orig_parts):
                continue
            orig_val = orig_parts[idx]
            # Infer type from samples
            sample_vals = [p[idx] for p in parts_all]
            ptype = self._infer_type_from_values(sample_vals)
            param_name = f"param_{idx}"
            orig_parts[idx] = "{" + param_name + "}"
            parameters.append(
                {
                    "name": param_name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": ptype},
                }
            )
        return "/".join(orig_parts), parameters

    def _infer_type_from_values(self, values: list[str]) -> str:
        """Infer JSON schema type from string values."""
        if all(self._is_int(v) for v in values):
            return "integer"
        if all(self._is_number(v) for v in values):
            return "number"
        if all(v.lower() in ("true", "false") for v in values):
            return "boolean"
        return "string"

    @staticmethod
    def _is_int(v: str) -> bool:
        try:
            int(v)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _is_number(v: str) -> bool:
        try:
            float(v)
            return True
        except (ValueError, TypeError):
            return False

    def infer_method_from_samples(self, method: str, responses: list[dict]) -> str:
        """Heuristic: refine HTTP method from response patterns."""
        method = method.upper()
        if method in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            return method
        if responses:
            statuses = {str(r.get("status", 0)) for r in responses if isinstance(r, dict)}
            if statuses and all(s.startswith("2") for s in statuses):
                return "GET"
            if statuses and any(s.startswith("2") for s in statuses):
                return "POST"
        return "GET"

    def merge_parameters(
        self, existing: list[dict], new: list[dict]
    ) -> list[dict]:
        """Merge parameter lists (same name+location -> deduplicate)."""
        seen: dict[str, int] = {}
        result: list[dict] = []
        for p in existing + new:
            if not isinstance(p, dict):
                continue
            key = f"{p.get('in', 'query')}:{p.get('name', '')}"
            if key not in seen:
                seen[key] = len(result)
                result.append(dict(p))
        return result

    def infer_status_codes(self, response_samples: list[dict]) -> dict[int, dict]:
        """Infer response schemas grouped by status code.

        Returns:
            dict mapping HTTP status code (int) to response schema dict with
            'description' and 'content' keys.
        """
        if not response_samples:
            return {}
        status_buckets: dict[str, list[Any]] = {}
        for rs in response_samples:
            if not isinstance(rs, dict):
                continue
            status = str(rs.get("status", 200))
            body = rs.get("body")
            if body is not None:
                status_buckets.setdefault(status, []).append(body)
        responses: dict[int, dict] = {}
        for status, bodies in sorted(status_buckets.items()):
            merged = self._sample_schema_merges(
                [self.infer_schema([b]) for b in bodies]
            )
            try:
                code = int(status)
            except (ValueError, TypeError):
                continue
            responses[code] = {
                "description": "",
                "content": {"application/json": {"schema": merged}},
            }
        return responses
