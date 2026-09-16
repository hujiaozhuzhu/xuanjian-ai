"""Tests for api_knowledge/visualize.py — HTML/JSON output and D3 keywords."""

from __future__ import annotations

import pytest
from fp_sentinel.api_knowledge.store import ApiKnowledgeStore, EndpointNode
from fp_sentinel.api_knowledge.visualize import (
    render_html,
    _graph_data,
    main as viz_main,
)


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_viz.db")
    s = ApiKnowledgeStore(db_path=db_path)
    s.open()
    eps = [
        EndpointNode(
            url="https://api.example.com/users/123",
            method="GET",
            parameters=[{"name": "id", "in": "path"}],
            response_schemas={"200": {"type": "object", "properties": {"name": {"type": "string"}}}},
            sensitivity="medium",
            source="har",
            tags=["user"],
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
            url="https://api.example.com/login",
            method="POST",
            parameters=[{"name": "username", "in": "body"}, {"name": "password", "in": "body"}],
            sensitivity="critical",
            source="static",
            tags=["auth"],
        ),
    ]
    for ep in eps:
        s.add_endpoint(ep)
    s.add_edge(eps[0].id, eps[1].id, 0.8, "test")
    yield s
    s.close()


class TestGraphData:
    def test_graph_data_has_nodes_and_links(self, store):
        data = _graph_data(store)
        assert "nodes" in data
        assert "links" in data
        assert len(data["nodes"]) == 3

    def test_graph_data_nodes_have_required_fields(self, store):
        data = _graph_data(store)
        for node in data["nodes"]:
            assert "id" in node
            assert "url" in node
            assert "method" in node
            assert "color" in node
            assert "radius" in node

    def test_graph_data_links_reference_valid_nodes(self, store):
        data = _graph_data(store)
        ids = {n["id"] for n in data["nodes"]}
        for link in data["links"]:
            assert link["source"] in ids
            assert link["target"] in ids


class TestRenderHtml:
    def test_html_not_empty(self, store):
        html = render_html(store)
        assert len(html) > 100

    def test_html_contains_d3_cdn(self, store):
        html = render_html(store)
        assert "d3js.org" in html or "d3.v7" in html

    def test_html_contains_graph_data(self, store):
        html = render_html(store)
        assert "DATA" in html

    def test_html_contains_method_labels(self, store):
        html = render_html(store)
        assert "GET" in html
        assert "POST" in html
        assert "DELETE" in html

    def test_html_contains_svg(self, store):
        html = render_html(store)
        assert "<svg" in html

    def test_html_is_self_contained(self, store):
        html = render_html(store)
        # No external stylesheet links
        assert "<link" not in html or "stylesheet" not in html


class TestVizMain:
    def test_json_output(self, store, tmp_path):
        out = str(tmp_path / "graph.json")
        rc = viz_main(["--db", store.db_path, "--format", "json", "--output", out])
        assert rc == 0
        import json
        data = json.loads(open(out, encoding="utf-8").read())
        assert len(data["nodes"]) == 3

    def test_html_output(self, store, tmp_path):
        out = str(tmp_path / "graph.html")
        rc = viz_main(["--db", store.db_path, "--format", "html", "--output", out])
        assert rc == 0
        content = open(out, encoding="utf-8").read()
        assert "<!DOCTYPE html>" in content

    def test_stdout_html(self, store, capsys):
        import sys
        rc = viz_main(["--db", store.db_path, "--format", "html", "--output", "-"])
        assert rc == 0
