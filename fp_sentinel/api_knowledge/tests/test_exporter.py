"""Tests for api_knowledge/exporter.py — OpenAPI 3.0.3 + HAR 1.2 builder."""

from __future__ import annotations

import json

import pytest
from fp_sentinel.api_knowledge.store import EndpointNode, ApiKnowledgeStore
from fp_sentinel.api_knowledge.exporter import (
    build_openapi_spec,
    build_har,
    export_to_json,
)


@pytest.fixture
def sample_eps():
    return [
        EndpointNode(
            url="https://api.example.com/users/123",
            method="GET",
            parameters=[
                {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
            ],
            response_schemas={
                "200": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "integer"},
                        "name": {"type": "string"},
                    },
                },
            },
            sensitivity="medium",
            source="har",
            tags=["user"],
        ),
        EndpointNode(
            url="https://api.example.com/users",
            method="POST",
            parameters=[],
            response_schemas={
                201: {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                    },
                },
            },
            sensitivity="high",
            source="har",
            tags=["user"],
        ),
    ]


class TestBuildOpenapiSpec:
    def test_valid_openapi_headers(self, sample_eps):
        spec = build_openapi_spec(sample_eps, title="Test API")
        assert spec["openapi"] == "3.0.3"
        assert spec["info"]["title"] == "Test API"
        assert spec["info"]["version"] == "1.0.0"
        assert "paths" in spec

    def test_paths_populated(self, sample_eps):
        spec = build_openapi_spec(sample_eps)
        paths = spec["paths"]
        assert "/users/123" in paths or any("users" in p for p in paths)

    def test_operations_have_responses(self, sample_eps):
        spec = build_openapi_spec(sample_eps)
        for path, ops in spec["paths"].items():
            for method, op in ops.items():
                assert "responses" in op
                assert len(op["responses"]) >= 1

    def test_empty_endpoints(self):
        spec = build_openapi_spec([])
        assert spec["paths"] == {}

    def test_default_title(self, sample_eps):
        spec = build_openapi_spec(sample_eps)
        assert spec["info"]["title"] == "Inferred Schema"


class TestBuildHar:
    def test_har_structure(self, sample_eps):
        har = build_har(sample_eps)
        assert "log" in har
        assert har["log"]["version"] == "1.2"
        assert "entries" in har["log"]
        assert len(har["log"]["entries"]) == len(sample_eps)

    def test_entry_request_response(self, sample_eps):
        har = build_har(sample_eps)
        entry = har["log"]["entries"][0]
        assert "request" in entry
        assert "response" in entry
        assert entry["request"]["method"] in {"GET", "POST"}
        assert entry["response"]["status"] == 200

    def test_har_creator_info(self, sample_eps):
        har = build_har(sample_eps)
        assert "creator" in har["log"]
        assert har["log"]["creator"]["name"] == "fp_sentinel-api_knowledge"

    def test_empty_har(self):
        har = build_har([])
        assert har["log"]["entries"] == []


class TestExportToJson:
    def test_export_creates_file(self, sample_eps, tmp_path):
        out = str(tmp_path / "output.json")
        result = export_to_json(sample_eps, out)
        assert result.endswith("output.json")
        data = json.loads(open(out, encoding="utf-8").read())
        assert len(data) == len(sample_eps)

    def test_export_content(self, sample_eps, tmp_path):
        out = str(tmp_path / "endpoints.json")
        export_to_json(sample_eps, out)
        data = json.loads(open(out, encoding="utf-8").read())
        assert data[0]["url"] == sample_eps[0].url
        assert data[0]["method"] == "GET"
        assert "id" in data[0]

    def test_export_empty(self, tmp_path):
        out = str(tmp_path / "empty.json")
        export_to_json([], out)
        data = json.loads(open(out, encoding="utf-8").read())
        assert data == []
