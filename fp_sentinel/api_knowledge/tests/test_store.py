"""Tests for api_knowledge/store.py — CRUD, graph queries, similarity."""

from __future__ import annotations

import pytest
from fp_sentinel.api_knowledge.store import ApiKnowledgeStore, EndpointNode


@pytest.fixture
def store(tmp_path):
    """Create a temporary in-memory-style store."""
    db_path = str(tmp_path / "test_api_kg.db")
    s = ApiKnowledgeStore(db_path=db_path)
    s.open()
    yield s
    s.close()


@pytest.fixture
def sample_eps():
    return [
        EndpointNode(
            url="https://api.example.com/users/123",
            method="GET",
            parameters=[{"name": "id", "in": "path", "type": "integer", "required": True}],
            response_schemas={"200": {"type": "object", "properties": {"user_id": {"type": "integer"}}}},
            sensitivity="medium",
            source="har",
            tags=["user"],
        ),
        EndpointNode(
            url="https://api.example.com/users/123/orders",
            method="GET",
            parameters=[{"name": "id", "in": "path", "type": "integer"}],
            response_schemas={"200": {"type": "object", "properties": {"user_id": {"type": "integer"}}}},
            sensitivity="high",
            source="har",
            tags=["order", "user"],
        ),
        EndpointNode(
            url="https://api.example.com/orders/456",
            method="DELETE",
            parameters=[{"name": "id", "in": "path"}],
            sensitivity="high",
            source="burp",
            tags=["order"],
        ),
        EndpointNode(
            url="https://third-party.com/data",
            method="GET",
            parameters=[],
            sensitivity="low",
            source="static",
            tags=["external"],
        ),
    ]


class TestCrud:
    def test_add_and_get(self, store, sample_eps):
        ep_id = store.add_endpoint(sample_eps[0])
        assert ep_id
        fetched = store.get_endpoint(ep_id)
        assert fetched is not None
        assert fetched.url == sample_eps[0].url
        assert fetched.method == "GET"

    def test_find_by_path(self, store, sample_eps):
        for ep in sample_eps:
            store.add_endpoint(ep)
        results = store.find_by_path("/users/")
        assert len(results) == 2

    def test_find_by_parameter(self, store, sample_eps):
        for ep in sample_eps:
            store.add_endpoint(ep)
        results = store.find_by_parameter("id")
        assert len(results) >= 3

    def test_count(self, store, sample_eps):
        for ep in sample_eps:
            store.add_endpoint(ep)
        assert store.count() == 4

    def test_upsert_same_id(self, store):
        ep = EndpointNode(url="/api/test", method="GET", id="same-id")
        store.add_endpoint(ep)
        ep2 = EndpointNode(url="/api/test-v2", method="POST", id="same-id")
        store.add_endpoint(ep2)
        assert store.count() == 1
        assert store.get_endpoint("same-id").method == "POST"


class TestGraphQueries:
    def test_neighbors(self, store, sample_eps):
        for ep in sample_eps:
            store.add_endpoint(ep)
        store.add_edge(sample_eps[0].id, sample_eps[1].id, 0.8, "test")
        store.add_edge(sample_eps[1].id, sample_eps[2].id, 0.5, "test")
        neighbors = store.get_neighbors(sample_eps[0].id, hops=2)
        assert len(neighbors) >= 2

    def test_find_chains(self, store, sample_eps):
        for ep in sample_eps:
            store.add_endpoint(ep)
        store.add_edge(sample_eps[0].id, sample_eps[1].id, 0.8, "test")
        store.add_edge(sample_eps[1].id, sample_eps[2].id, 0.5, "test")
        chains = store.find_chains(sample_eps[0].id, max_depth=4)
        assert len(chains) >= 1


class TestSimilarity:
    def test_high_similarity(self, store):
        a = EndpointNode(url="/api/users/123", method="GET", parameters=[{"name": "id", "in": "path"}])
        b = EndpointNode(url="/api/users/456", method="GET", parameters=[{"name": "id", "in": "path"}])
        score = store.similarity(a, b)
        assert score > 0.5

    def test_low_similarity(self, store):
        a = EndpointNode(url="/api/users/list", method="GET")
        b = EndpointNode(url="https://other.com/config", method="POST")
        score = store.similarity(a, b)
        assert score < 0.5


class TestFullTextSearch:
    def test_search(self, store, sample_eps):
        for ep in sample_eps:
            store.add_endpoint(ep)
        results = store.search("users")
        assert len(results) >= 2

    def test_search_by_tag(self, store, sample_eps):
        for ep in sample_eps:
            store.add_endpoint(ep)
        results = store.search("order")
        assert len(results) >= 1


class TestStats:
    def test_stats(self, store, sample_eps):
        for ep in sample_eps:
            store.add_endpoint(ep)
        stats = store.stats()
        assert stats["endpoints"] == 4
        assert "by_method" in stats
        assert "by_sensitivity" in stats
