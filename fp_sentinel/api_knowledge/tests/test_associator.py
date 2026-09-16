"""Tests for api_knowledge/associator.py — linking, islands, bottlenecks, BOLA."""

from __future__ import annotations

import pytest
from fp_sentinel.api_knowledge.store import ApiKnowledgeStore, EndpointNode
from fp_sentinel.api_knowledge.associator import ApiAssociator


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_assoc.db")
    s = ApiKnowledgeStore(db_path=db_path)
    s.open()
    yield s
    s.close()


@pytest.fixture
def associator():
    return ApiAssociator()


def _make_ep(url, method="GET", params=None, scheme=None, sens="medium", tag=""):
    return EndpointNode(
        url=url,
        method=method,
        parameters=params or [],
        response_schemas=scheme or {},
        sensitivity=sens,
        tags=[tag] if tag else [],
    )


class TestLinkEndpoints:
    def test_links_on_shared_params(self, store, associator):
        eps = [
            _make_ep("/api/users/123", params=[{"name": "id", "in": "path"}]),
            _make_ep("/api/users/456", params=[{"name": "id", "in": "path"}]),
        ]
        for ep in eps:
            store.add_endpoint(ep)
        count = associator.link_endpoints(store, threshold=0.1)
        assert count >= 1

    def test_links_on_source_chain(self, store, associator):
        eps = [
            _make_ep("/api/login", "POST", scheme={"200": {"type": "object", "properties": {"user_id": {"type": "integer"}}}}),
            _make_ep("/api/users/123", "GET", params=[{"name": "user_id", "in": "path"}]),
        ]
        for ep in eps:
            store.add_endpoint(ep)
        count = associator.link_endpoints(store, threshold=0.1)
        assert count >= 1


class TestAssociateSharedParameter:
    def test_full_overlap(self, associator):
        a = _make_ep("/a", params=[{"name": "id"}, {"name": "page"}])
        b = _make_ep("/b", params=[{"name": "id"}, {"name": "page"}])
        assert associator.associate_shared_parameter(a, b) == pytest.approx(1.0)

    def test_no_overlap(self, associator):
        a = _make_ep("/a", params=[{"name": "x"}])
        b = _make_ep("/b", params=[{"name": "y"}])
        assert associator.associate_shared_parameter(a, b) == pytest.approx(0.0)

    def test_no_params(self, associator):
        a = _make_ep("/a")
        b = _make_ep("/b")
        assert associator.associate_shared_parameter(a, b) == 0.0


class TestAssociateSchemaOverlap:
    def test_full_overlap(self, associator):
        schema = {"200": {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}}}
        a = _make_ep("/a", scheme=schema)
        b = _make_ep("/b", scheme=schema)
        assert associator.associate_schema_overlap(a, b) == pytest.approx(1.0)

    def test_no_overlap(self, associator):
        a = _make_ep("/a", scheme={"200": {"type": "object", "properties": {"id": {"type": "integer"}}}})
        b = _make_ep("/b", scheme={"200": {"type": "object", "properties": {"name": {"type": "string"}}}})
        assert associator.associate_schema_overlap(a, b) == pytest.approx(0.0)


class TestAssociateSourceChain:
    def test_chain_detected(self, associator):
        a = _make_ep("/login", "POST", scheme={"200": {"type": "object", "properties": {"user_id": {"type": "integer"}}}})
        b = _make_ep("/users/user_id", "GET", params=[{"name": "user_id", "in": "path"}])
        score = associator.associate_source_chain(a, b)
        assert score > 0.0


class TestFindIslands:
    def test_single_island(self, store, associator):
        eps = [
            _make_ep("/api/users/123", params=[{"name": "id"}]),
            _make_ep("/api/users/456", params=[{"name": "id"}]),
        ]
        for ep in eps:
            store.add_endpoint(ep)
        associator.link_endpoints(store)
        islands = associator.find_islands(store)
        assert len(islands) == 1

    def test_two_islands(self, store, associator):
        eps = [
            _make_ep("/api/internal/users", params=[{"name": "page"}]),
            _make_ep("/api/internal/posts", params=[{"name": "page"}]),
            _make_ep("/external/captcha", params=[]),
        ]
        for ep in eps:
            store.add_endpoint(ep)
        associator.link_endpoints(store)
        islands = associator.find_islands(store)
        assert len(islands) >= 1


class TestFindBottlenecks:
    def test_no_edges(self, store, associator):
        eps = [_make_ep("/a"), _make_ep("/b")]
        for ep in eps:
            store.add_endpoint(ep)
        bottlenecks = associator.find_bottlenecks(store)
        assert len(bottlenecks) == 0

    def test_central_node(self, store, associator):
        central = _make_ep("/api/users/123", params=[{"name": "id"}])
        leaf1 = _make_ep("/api/users/456", params=[{"name": "id"}])
        leaf2 = _make_ep("/api/users/789", params=[{"name": "id"}])
        for ep in [central, leaf1, leaf2]:
            store.add_endpoint(ep)
        store.add_edge(leaf1.id, central.id, 0.5, "test")
        store.add_edge(leaf2.id, central.id, 0.6, "test")
        bottlenecks = associator.find_bottlenecks(store)
        assert len(bottlenecks) >= 1
        assert bottlenecks[0][1] == 2


class TestFindHorizontalAttackSurface:
    def test_bola_detected(self, store, associator):
        eps = [
            _make_ep("/api/users/123", "DELETE", params=[{"name": "id", "in": "path"}], sens="high"),
            _make_ep("/api/orders/456", "PUT", params=[{"name": "id", "in": "path"}], sens="high"),
        ]
        for ep in eps:
            store.add_endpoint(ep)
        risks = associator.find_horizontal_attack_surface(store)
        assert len(risks) >= 2

    def test_safe_endpoints_low_risk(self, store, associator):
        eps = [
            _make_ep("/api/health", "GET", sens="low"),
            _make_ep("/api/config", "OPTIONS", sens="low"),
        ]
        for ep in eps:
            store.add_endpoint(ep)
        risks = associator.find_horizontal_attack_surface(store)
        assert len(risks) == 0

    def test_userid_param_detected(self, store, associator):
        eps = [
            _make_ep("/api/profile", "GET", params=[{"name": "userid", "in": "query"}], sens="high"),
        ]
        for ep in eps:
            store.add_endpoint(ep)
        risks = associator.find_horizontal_attack_surface(store)
        assert len(risks) >= 1
