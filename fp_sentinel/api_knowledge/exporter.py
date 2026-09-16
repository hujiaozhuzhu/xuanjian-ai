"""OpenAPI 3.0.3 + HAR 1.2 exporters.

Assembles complete API specification documents from EndpointNode collections,
or serializes endpoint lists as JSON.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .store import EndpointNode


def build_openapi_spec(
    eps: List[EndpointNode],
    title: str = "Inferred Schema",
) -> dict:
    """Assemble an OpenAPI 3.0.3 document from endpoint nodes.

    Args:
        eps: List of EndpointNode instances.
        title: Document title.

    Returns:
        dict: OpenAPI 3.0.3 specification.
    """
    paths: dict = {}
    for ep in eps:
        url = ep.url or "/"
        path = url.split("?")[0] if "?" in url else url
        if not path:
            path = "/"
        method = (ep.method or "GET").lower()
        operation: dict = {"summary": f"{ep.method} {path}"}
        if ep.parameters:
            operation["parameters"] = ep.parameters
        if ep.response_schemas:
            operation["responses"] = {
                str(status): {
                    "description": "",
                    "content": {"application/json": {"schema": schema}},
                }
                for status, schema in ep.response_schemas.items()
                if isinstance(schema, dict)
            }
        if "responses" not in operation:
            operation["responses"] = {"200": {"description": ""}}
        paths.setdefault(path, {})[method] = operation

    return {
        "openapi": "3.0.3",
        "info": {
            "title": title,
            "version": "1.0.0",
            "description": f"Auto-inferred API schema ({len(eps)} endpoints)",
        },
        "paths": paths,
    }


def build_har(eps: List[EndpointNode]) -> dict:
    """Generate a HAR 1.2 format document from endpoint nodes.

    Synthesizes plausible request/response entries using each endpoint's
    parameters and response schemas.

    Args:
        eps: List of EndpointNode instances.

    Returns:
        dict: HAR 1.2 document with ``log.entries``.
    """
    entries: list[dict] = []
    for ep in eps:
        url = ep.url or "/"
        method = (ep.method or "GET").upper()
        entry: dict = {
            "startedDateTime": datetime.now(timezone.utc).isoformat(),
            "time": 0,
            "request": {
                "method": method,
                "url": url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [
                    {"name": "Content-Type", "value": "application/json"},
                    {"name": "Accept", "value": "application/json"},
                ],
                "queryString": [],
                "headersSize": -1,
                "bodySize": 0,
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [
                    {"name": "Content-Type", "value": "application/json"},
                ],
                "content": {
                    "size": 0,
                    "mimeType": "application/json",
                    "text": json.dumps(ep.response_schemas.get("200", {})),
                },
                "headersSize": -1,
                "bodySize": 0,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0},
        }
        params = ep.parameters or []
        query_params = [
            {"name": p.get("name", ""), "value": str(p.get("example", ""))}
            for p in params
            if isinstance(p, dict) and p.get("in") == "query"
        ]
        entry["request"]["queryString"] = query_params
        entries.append(entry)

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "fp_sentinel-api_knowledge", "version": "1.0"},
            "entries": entries,
        }
    }


def export_to_json(
    eps: List[EndpointNode],
    out_path: str,
) -> str:
    """Export an endpoint list as JSON.

    Each endpoint is serialized with its id, url, method, path_template,
    parameters, request_schema, response_schemas, sensitivity, source, tags.

    Args:
        eps: List of EndpointNode instances.
        out_path: Destination file path.

    Returns:
        str: Absolute path of the written file.
    """
    records = []
    for ep in eps:
        records.append({
            "id": ep.id,
            "url": ep.url,
            "method": ep.method,
            "path_template": ep.path_template,
            "parameters": ep.parameters,
            "request_schema": ep.request_schema,
            "response_schemas": ep.response_schemas,
            "references": ep.references,
            "sensitivity": ep.sensitivity,
            "source": ep.source,
            "tags": ep.tags,
        })
    payload = json.dumps(records, ensure_ascii=False, indent=2, default=str)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(payload, encoding="utf-8")
    return str(Path(out_path).resolve())
