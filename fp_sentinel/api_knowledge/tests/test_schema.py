"""Tests for api_knowledge/schema_infer.py — schema inference, path params, method."""

from __future__ import annotations

import pytest
from fp_sentinel.api_knowledge.schema_infer import SchemaInferer


@pytest.fixture
def inferer():
    return SchemaInferer()


class TestPythonTypeToSchema:
    def test_int(self, inferer):
        assert inferer._python_type_to_schema(42) == {"type": "integer"}

    def test_float(self, inferer):
        assert inferer._python_type_to_schema(3.14) == {"type": "number"}

    def test_bool(self, inferer):
        assert inferer._python_type_to_schema(True) == {"type": "boolean"}

    def test_null(self, inferer):
        assert inferer._python_type_to_schema(None) == {"type": "null"}

    def test_string(self, inferer):
        assert inferer._python_type_to_schema("hello") == {"type": "string"}

    def test_email(self, inferer):
        result = inferer._python_type_to_schema("test@example.com")
        assert result.get("format") == "email"

    def test_uuid(self, inferer):
        result = inferer._python_type_to_schema("550e8400-e29b-41d4-a716-446655440000")
        assert result.get("format") == "uuid"

    def test_nested_dict(self, inferer):
        result = inferer._python_type_to_schema({"name": "alice", "age": 30})
        assert result["type"] == "object"
        assert "name" in result["properties"]
        assert "age" in result["properties"]

    def test_list(self, inferer):
        result = inferer._python_type_to_schema([1, 2, 3])
        assert result["type"] == "array"


class TestInferSchema:
    def test_single_sample(self, inferer):
        result = inferer.infer_schema([{"id": 1, "name": "test"}])
        assert result["type"] == "object"
        assert "id" in result.get("properties", {})

    def test_merge_samples_required(self, inferer):
        result = inferer.infer_schema([
            {"id": 1, "name": "a"},
            {"id": 2, "name": "b"},
            {"id": 3, "name": "c"},
            {"id": 4, "name": "d"},
            {"id": 5, "name": "e"},
        ])
        assert "required" in result
        assert "id" in result["required"]
        assert "name" in result["required"]

    def test_merge_partial_required(self, inferer):
        # email appears in 3/5 = 60% (below 80% threshold), id in all 5 = 100%
        samples = [
            {"id": 1, "email": "a@x.com"},
            {"id": 2, "email": "b@x.com"},
            {"id": 3, "email": "c@x.com"},
            {"id": 4},
            {"id": 5},
        ]
        result = inferer.infer_schema(samples)
        assert "id" in result.get("required", [])
        assert "email" not in result.get("required", [])

    def test_mixed_types_oneOf(self, inferer):
        result = inferer.infer_schema([1, "two"])
        assert "oneOf" in result


class TestExtractPathParams:
    def test_basic_params(self, inferer):
        path, params = inferer.extract_path_params(
            "/api/user/123",
            ["/api/user/123", "/api/user/456", "/api/user/789"],
        )
        assert "/api/user/" in path
        assert len(params) >= 1
        assert params[0]["name"].startswith("param_")

    def test_no_variation(self, inferer):
        path, params = inferer.extract_path_params(
            "/api/user/list",
            ["/api/user/list", "/api/user/list"],
        )
        assert params == []

    def test_single_sample_no_params(self, inferer):
        path, params = inferer.extract_path_params("/api/test", [])
        assert params == []


class TestInferMethod:
    def test_known_method(self, inferer):
        assert inferer.infer_method_from_samples("DELETE", []) == "DELETE"

    def test_unknown_defaults_get(self, inferer):
        assert inferer.infer_method_from_samples("UNKNOWN", []) == "GET"


class TestMergeParameters:
    def test_merge_no_dup(self, inferer):
        merged = inferer.merge_parameters(
            [{"name": "page", "in": "query"}],
            [{"name": "limit", "in": "query"}],
        )
        assert len(merged) == 2

    def test_merge_dedup(self, inferer):
        merged = inferer.merge_parameters(
            [{"name": "id", "in": "query"}],
            [{"name": "id", "in": "query"}],
        )
        assert len(merged) == 1


class TestInferFromSamples:
    def test_basic_request_response(self, inferer):
        result = inferer.infer_from_samples(
            "POST",
            "https://api.example.com/users",
            request_samples=[
                {"body": {"name": "alice", "email": "alice@example.com"}},
            ],
            response_samples=[
                {"status": 201, "body": {"id": 1, "name": "alice"}},
            ],
        )
        assert "paths" in result

    def test_empty_samples(self, inferer):
        result = inferer.infer_from_samples("GET", "https://api.example.com/data")
        assert "paths" in result
