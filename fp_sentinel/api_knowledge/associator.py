"""API endpoint relationship analyzer + attack surface discovery.

Implements graph-based relationship discovery and security analysis
strategies inspired by GraphRaptor/GraphRAG.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from .store import ApiKnowledgeStore, EndpointNode


def _param_names(ep: EndpointNode) -> Set[str]:
    """Extract parameter name set from an endpoint."""
    names: set[str] = set()
    for p in ep.parameters:
        if isinstance(p, dict) and p.get("name"):
            names.add(p["name"])
        elif isinstance(p, str):
            names.add(p)
    return names


def _leaf_fields(schema: dict | str | None) -> Set[str]:
    """Recursively collect all leaf field names from a JSON schema."""
    fields: set[str] = set()
    if isinstance(schema, str):
        try:
            schema = json.loads(schema)
        except (json.JSONDecodeError, TypeError):
            return fields
    if not isinstance(schema, dict):
        return fields

    def _walk(s: dict) -> None:
        if not isinstance(s, dict):
            return
        props = s.get("properties", {})
        if isinstance(props, dict):
            for k, v in props.items():
                fields.add(k)
                if isinstance(v, dict):
                    _walk(v)
        items = s.get("items")
        if isinstance(items, dict):
            _walk(items)

    _walk(schema)
    # If it looks like a {status: schema} dict, walk each
    if "type" not in schema and "properties" not in schema:
        for status, resp in schema.items():
            if isinstance(resp, dict):
                _walk(resp)
    return fields


class ApiAssociator:
    """Analyzes endpoint relationships and discovers attack surface patterns."""

    def link_endpoints(self, store: ApiKnowledgeStore, threshold: float = 0.3) -> int:
        """Traverse all endpoints in store, create edges for strong associations.

        Returns:
            int: Number of new edges created.
        """
        eps = store.all_endpoints()
        if len(eps) < 2:
            return 0
        edges_created = 0
        for i, a in enumerate(eps):
            for b in eps[i + 1:]:
                score = self._combined_score(a, b)
                if score >= threshold:
                    store.add_edge(a.id, b.id, score, "auto-linked")
                    edges_created += 1
        return edges_created

    def _combined_score(self, a: EndpointNode, b: EndpointNode) -> float:
        """Aggregate association score across all strategies."""
        return (
            self.associate_shared_parameter(a, b) * 0.3
            + self.associate_schema_overlap(a, b) * 0.25
            + self.associate_source_chain(a, b) * 0.25
            + self.associate_tag_overlap(a, b) * 0.1
            + self.associate_sensitivity(a, b) * 0.1
        )

    def associate_shared_parameter(self, ep_a: EndpointNode, ep_b: EndpointNode) -> float:
        """Jaccard coefficient of shared parameter names."""
        params_a = _param_names(ep_a)
        params_b = _param_names(ep_b)
        if not params_a or not params_b:
            return 0.0
        intersection = params_a & params_b
        union = params_a | params_b
        return len(intersection) / len(union)

    def associate_schema_overlap(self, ep_a: EndpointNode, ep_b: EndpointNode) -> float:
        """Leaf field set Jaccard between two endpoints' response schemas."""
        fields_a: set[str] = set()
        fields_b: set[str] = set()
        if isinstance(ep_a.response_schemas, dict):
            for v in ep_a.response_schemas.values():
                fields_a |= _leaf_fields(v)
        if isinstance(ep_b.response_schemas, dict):
            for v in ep_b.response_schemas.values():
                fields_b |= _leaf_fields(v)
        if not fields_a or not fields_b:
            return 0.0
        intersection = fields_a & fields_b
        union = fields_a | fields_b
        return len(intersection) / len(union)

    def associate_source_chain(self, ep_a: EndpointNode, ep_b: EndpointNode) -> float:
        """Detect calling-chain relationships.

        If endpoint A's response contains a field whose name matches endpoint B's
        path/query parameter, likely B can be invoked with data from A.
        """
        a_fields: set[str] = set()
        if isinstance(ep_a.response_schemas, dict):
            for v in ep_a.response_schemas.values():
                a_fields |= _leaf_fields(v)
        b_params = _param_names(ep_b)
        for seg in ep_b.url.split("/"):
            seg_clean = seg.strip("{}").lower()
            if seg_clean and len(seg_clean) > 1:
                b_params.add(seg_clean)
        if not a_fields or not b_params:
            return 0.0
        intersection = a_fields & b_params
        return min(1.0, len(intersection) / min(len(a_fields), len(b_params)))

    def associate_tag_overlap(self, ep_a: EndpointNode, ep_b: EndpointNode) -> float:
        """Jaccard coefficient of tag sets."""
        tags_a = set(ep_a.tags) if ep_a.tags else set()
        tags_b = set(ep_b.tags) if ep_b.tags else set()
        if not tags_a or not tags_b:
            return 0.0
        intersection = tags_a & tags_b
        union = tags_a | tags_b
        return len(intersection) / len(union)

    def associate_sensitivity(self, ep_a: EndpointNode, ep_b: EndpointNode) -> float:
        """Score if both endpoints share high sensitivity."""
        HIGH = {"CRITICAL", "HIGH", "high"}
        sens_a = ep_a.sensitivity.upper() if ep_a.sensitivity else ""
        sens_b = ep_b.sensitivity.upper() if ep_b.sensitivity else ""
        if sens_a in HIGH and sens_b in HIGH:
            return 0.8 if ep_a.tags and ep_b.tags and set(ep_a.tags) & set(ep_b.tags) else 0.5
        return 0.0

    def find_islands(self, store: ApiKnowledgeStore) -> List[List[str]]:
        """Find disconnected subgraphs (isolated endpoint clusters).

        Typically corresponds to third-party APIs.

        Returns:
            List of clusters, each being a list of endpoint IDs.
        """
        eps = store.all_endpoints()
        if not eps:
            return []
        adj: dict[str, set[str]] = defaultdict(set)
        ids = {ep.id for ep in eps}
        cur = store.conn.execute(
            "SELECT source_id, target_id FROM endpoint_edges"
        )
        for row in cur.fetchall():
            src, tgt = row[0], row[1]
            if src in ids and tgt in ids:
                adj[src].add(tgt)
                adj[tgt].add(src)
        visited: set[str] = set()
        clusters: list[list[str]] = []
        for ep in eps:
            if ep.id in visited:
                continue
            cluster: list[str] = []
            queue = [ep.id]
            while queue:
                node = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                cluster.append(node)
                for neighbor in adj.get(node, set()):
                    if neighbor not in visited:
                        queue.append(neighbor)
            clusters.append(cluster)
        return clusters

    def find_bottlenecks(self, store: ApiKnowledgeStore) -> List[Tuple[str, int]]:
        """Find high in-degree nodes (core dependencies).

        Returns:
            List of (endpoint_id, in_degree) sorted by degree desc.
        """
        cur = store.conn.execute(
            """SELECT target_id, COUNT(*) as deg FROM endpoint_edges
               GROUP BY target_id ORDER BY deg DESC""",
        )
        return [(row[0], row[1]) for row in cur.fetchall()]

    def find_horizontal_attack_surface(
        self,
        store: ApiKnowledgeStore,
        candidate_params: tuple[str, ...] = ("id", "user_id", "order_id"),
    ) -> List[dict]:
        """Find suspected BOLA/IDOR endpoints.

        Criteria: path containing object-id-like patterns + GET/PUT/DELETE/PATCH method.

        Args:
            store: The API knowledge store.
            candidate_params: Tuple of parameter names that indicate BOLA risk.

        Returns:
            List of dicts with endpoint info and risk indicators.
        """
        SAFE_METHODS = {"OPTIONS", "HEAD"}
        DANGEROUS_METHODS = {"GET", "PUT", "DELETE", "PATCH"}
        risk_indicators: list[dict] = []
        eps = store.all_endpoints()
        for ep in eps:
            method = (ep.method or "GET").upper()
            if method in SAFE_METHODS or method not in DANGEROUS_METHODS:
                continue
            url = ep.url or ""
            is_bola = False
            reasons: list[str] = []
            if "/{" in url or re.search(r"/\d+", url) or re.search(r"/[0-9a-f]{8}-", url, re.I):
                is_bola = True
                reasons.append("path_contains_object_id_pattern")
            params = _param_names(ep)
            for p in params:
                p_lower = p.lower()
                if p_lower in candidate_params or p_lower in {"userid", "uuid", "entityid", "resourceid"}:
                    is_bola = True
                    reasons.append(f"param_matches_{p_lower}")
            if is_bola:
                # Check for sensitive fields in response schema
                shared_fields: list[str] = []
                if isinstance(ep.response_schemas, dict):
                    for v in ep.response_schemas.values():
                        shared_fields.extend(_leaf_fields(v))
                risk_indicators.append(
                    {
                        "endpoint_ids": [ep.id],
                        "param": next((p for p in params if p.lower() in candidate_params), ""),
                        "risk": "BOLA/IDOR",
                        "method": method,
                        "url": url,
                        "shared_fields": shared_fields[:20],
                    }
                )
        return risk_indicators

    def build_attack_surface_report(self, store: ApiKnowledgeStore) -> str:
        """Generate a Markdown attack surface report.

        Returns:
            str: Multi-section Markdown report string.
        """
        bottlenecks = self.find_bottlenecks(store)
        islands = self.find_islands(store)
        bola = self.find_horizontal_attack_surface(store)
        stats = store.stats()

        lines: list[str] = [
            "# API Attack Surface Report",
            "",
            f"**Generated from**: {stats['endpoints']} endpoints, {stats['edges']} edges",
            "",
            "## Summary",
            "",
            f"- Total endpoints: {stats['endpoints']}",
            f"- Total edges: {stats['edges']}",
            f"- Disconnected islands: {len(islands)}",
            f"- Bottleneck nodes: {len(bottlenecks)}",
            f"- BOLA/IDOR risks: {len(bola)}",
            "",
            "## Method Distribution",
            "",
        ]
        for mth, cnt in sorted(stats.get("by_method", {}).items(), key=lambda x: -x[1]):
            lines.append(f"- {mth}: {cnt}")

        lines.append("")
        lines.append("## Sensitivity Distribution")
        lines.append("")
        for sns, cnt in sorted(stats.get("by_sensitivity", {}).items(), key=lambda x: -x[1]):
            lines.append(f"- {sns}: {cnt}")

        lines.append("")
        lines.append("## Bottleneck Nodes (by in-degree)")
        lines.append("")
        if bottlenecks:
            for eid, deg in bottlenecks[:20]:
                ep = store.get_endpoint(eid)
                label = f"{ep.method} {ep.url}" if ep else eid
                lines.append(f"- **{label}** (in-degree: {deg})")
        else:
            lines.append("- No bottleneck nodes detected.")

        lines.append("")
        lines.append("## Disconnected Islands")
        lines.append("")
        for i, cluster in enumerate(islands, 1):
            lines.append(f"- Island {i}: {len(cluster)} endpoints")
            for eid in cluster[:3]:
                ep = store.get_endpoint(eid)
                if ep:
                    lines.append(f"  - {ep.method} {ep.url}")
            if len(cluster) > 3:
                lines.append(f"  - ... and {len(cluster) - 3} more")

        lines.append("")
        lines.append("## BOLA/IDOR Risks")
        lines.append("")
        if bola:
            for risk in bola:
                lines.append(f"- **{risk['method']} {risk['url']}**")
                lines.append(f"  - Risk: {risk['risk']}")
                if risk.get("param"):
                    lines.append(f"  - Sensitive param: `{risk['param']}`")
                if risk.get("shared_fields"):
                    lines.append(f"  - Response fields: {', '.join(risk['shared_fields'][:5])}")
        else:
            lines.append("- No BOLA/IDOR risks detected.")

        lines.append("")
        return "\n".join(lines)
