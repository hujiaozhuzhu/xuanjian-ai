"""GraphRAG-style API knowledge storage — SQLite + FTS5 full-text search.

Provides EndpointNode CRUD, graph queries (neighbors, chains),
and similarity scoring between endpoints.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class EndpointNode:
    """Single API endpoint abstraction."""

    id: str = ""
    url: str = ""
    method: str = "GET"
    path_template: str = ""
    parameters: list = field(default_factory=list)
    request_schema: Optional[dict] = None
    response_schemas: dict = field(default_factory=dict)
    references: list = field(default_factory=list)
    sensitivity: str = "medium"
    source: str = "static"
    tags: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id and (self.url or self.path_template or self.method):
            src = f"{self.method.upper()}|{self.path_template or self.url}"
            self.id = hashlib.md5(src.encode()).hexdigest()[:16]


# ── Schema DDL (list of individual statements to avoid ";" splitting bugs) ──

_SCHEMA_STATEMENTS: list[str] = [
    """CREATE TABLE IF NOT EXISTS endpoints (
        id              TEXT PRIMARY KEY,
        url             TEXT NOT NULL,
        method          TEXT DEFAULT 'GET',
        path_template   TEXT DEFAULT '',
        parameters      TEXT DEFAULT '[]',
        request_schema  TEXT DEFAULT '',
        response_schemas TEXT DEFAULT '{}',
        linked_refs     TEXT DEFAULT '[]',
        sensitivity     TEXT DEFAULT 'medium',
        source          TEXT DEFAULT 'static',
        tags            TEXT DEFAULT '[]',
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    "CREATE INDEX IF NOT EXISTS idx_ep_method ON endpoints(method)",
    "CREATE INDEX IF NOT EXISTS idx_ep_sensitivity ON endpoints(sensitivity)",
    "CREATE INDEX IF NOT EXISTS idx_ep_source ON endpoints(source)",
    """CREATE VIRTUAL TABLE IF NOT EXISTS endpoints_fts USING fts5(
        url, path_template, method, sensitivity, tags
    )""",
    """CREATE TRIGGER IF NOT EXISTS endpoints_ai AFTER INSERT ON endpoints BEGIN
        INSERT INTO endpoints_fts(rowid, url, path_template, method, sensitivity, tags)
        VALUES (new.rowid, new.url, new.path_template, new.method, new.sensitivity, new.tags);
    END""",
    """CREATE TRIGGER IF NOT EXISTS endpoints_ad AFTER DELETE ON endpoints BEGIN
        INSERT INTO endpoints_fts(endpoints_fts, rowid, url, path_template, method, sensitivity, tags)
        VALUES('delete', old.rowid, old.url, old.path_template, old.method, old.sensitivity, old.tags);
    END""",
    """CREATE TRIGGER IF NOT EXISTS endpoints_au AFTER UPDATE ON endpoints BEGIN
        INSERT INTO endpoints_fts(endpoints_fts, rowid, url, path_template, method, sensitivity, tags)
        VALUES('delete', old.rowid, old.url, old.path_template, old.method, old.sensitivity, old.tags);
        INSERT INTO endpoints_fts(rowid, url, path_template, method, sensitivity, tags)
        VALUES (new.rowid, new.url, new.path_template, new.method, new.sensitivity, new.tags);
    END""",
    """CREATE TABLE IF NOT EXISTS endpoint_edges (
        source_id   TEXT NOT NULL,
        target_id   TEXT NOT NULL,
        weight      REAL DEFAULT 0.0,
        reason      TEXT DEFAULT '',
        PRIMARY KEY (source_id, target_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_edges_source ON endpoint_edges(source_id)",
    "CREATE INDEX IF NOT EXISTS idx_edges_target ON endpoint_edges(target_id)",
]


def _row_to_node(row: sqlite3.Row) -> EndpointNode:
    """Convert a database row to EndpointNode."""
    d = dict(row)
    for key in ("parameters", "response_schemas", "references", "tags"):
        val = d.get(key, "[]")
        if isinstance(val, str):
            try:
                d[key] = json.loads(val) if val else []
            except json.JSONDecodeError:
                d[key] = []
    req_schema_raw = d.get("request_schema", "")
    request_schema: Optional[dict] = None
    if isinstance(req_schema_raw, str) and req_schema_raw:
        try:
            request_schema = json.loads(req_schema_raw)
        except json.JSONDecodeError:
            request_schema = None
    return EndpointNode(
        id=d.get("id", ""),
        url=d.get("url", ""),
        method=d.get("method", "GET"),
        path_template=d.get("path_template", ""),
        parameters=d.get("parameters", []),
        request_schema=request_schema,
        response_schemas=d.get("response_schemas", {}),
        references=d.get("linked_refs", []),
        sensitivity=d.get("sensitivity", "medium"),
        source=d.get("source", "static"),
        tags=d.get("tags", []),
    )


class ApiKnowledgeStore:
    """API knowledge graph store — SQLite backend with FTS5 full-text search.

    Zero external dependencies (stdlib sqlite3 only), thread-safe via
    check_same_thread=False for cross-thread use.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".xuanjian", "api_knowledge.db"
        )
        self._conn: Optional[sqlite3.Connection] = None

    def open(self) -> "ApiKnowledgeStore":
        """Open connection and initialize schema."""
        dirpath = os.path.dirname(self.db_path)
        if dirpath and self.db_path != ":memory:":
            os.makedirs(dirpath, exist_ok=True)
        self._conn = sqlite3.connect(
            self.db_path, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        for stmt in _SCHEMA_STATEMENTS:
            stmt = stmt.strip()
            if stmt:
                try:
                    self._conn.execute(stmt)
                except sqlite3.OperationalError as e:
                    if "already exists" not in str(e):
                        raise
        self._conn.commit()
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("store not opened")
        return self._conn

    def __enter__(self) -> "ApiKnowledgeStore":
        return self.open()

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ────── CRUD ──────

    def add_endpoint(self, ep: EndpointNode) -> str:
        """Insert or replace an endpoint. Returns the endpoint id."""
        if not ep.id:
            ep.__post_init__()
        req_str = json.dumps(ep.request_schema, ensure_ascii=False) if ep.request_schema else ""
        tags_str = " ".join(ep.tags)
        self.conn.execute(
            """INSERT OR REPLACE INTO endpoints
               (id, url, method, path_template, parameters, request_schema,
                response_schemas, linked_refs, sensitivity, source, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ep.id,
                ep.url,
                ep.method.upper(),
                ep.path_template or "",
                json.dumps(ep.parameters, ensure_ascii=False),
                req_str,
                json.dumps(ep.response_schemas, ensure_ascii=False),
                json.dumps(ep.references, ensure_ascii=False),
                ep.sensitivity,
                ep.source,
                json.dumps(ep.tags, ensure_ascii=False),
            ),
        )
        self.conn.commit()
        # Sync FTS index
        self._sync_fts(ep.id, ep.url, ep.path_template, ep.method, ep.sensitivity, tags_str)
        return ep.id

    def _sync_fts(self, ep_id: str, url: str, path_template: str, method: str, sensitivity: str, tags_str: str) -> None:
        """Update FTS index for a single endpoint."""
        self.conn.execute(
            "DELETE FROM endpoints_fts WHERE rowid = (SELECT rowid FROM endpoints WHERE id = ?)",
            (ep_id,),
        )
        self.conn.execute(
            """INSERT INTO endpoints_fts (rowid, url, path_template, method, sensitivity, tags)
               VALUES ((SELECT rowid FROM endpoints WHERE id = ?), ?, ?, ?, ?, ?)""",
            (ep_id, url, path_template or "", method.upper(), sensitivity, tags_str),
        )
        self.conn.commit()

    def get_endpoint(self, ep_id: str) -> Optional[EndpointNode]:
        """Fetch a single endpoint by id."""
        cur = self.conn.execute(
            "SELECT * FROM endpoints WHERE id = ?", (ep_id,)
        )
        row = cur.fetchone()
        return _row_to_node(row) if row else None

    def find_by_path(self, path_pattern: str) -> List[EndpointNode]:
        """Find endpoints whose path/url matches a LIKE pattern."""
        cur = self.conn.execute(
            "SELECT * FROM endpoints WHERE url LIKE ? OR path_template LIKE ?",
            (f"%{path_pattern}%", f"%{path_pattern}%"),
        )
        return [_row_to_node(r) for r in cur.fetchall()]

    def find_by_parameter(self, param_name: str) -> List[EndpointNode]:
        """Find endpoints that contain a given parameter name (JSON search)."""
        cur = self.conn.execute(
            "SELECT * FROM endpoints WHERE parameters LIKE ?",
            (f"%{param_name}%",),
        )
        return [_row_to_node(r) for r in cur.fetchall()]

    def all_endpoints(self) -> List[EndpointNode]:
        """Return all endpoints."""
        cur = self.conn.execute("SELECT * FROM endpoints")
        return [_row_to_node(r) for r in cur.fetchall()]

    def count(self) -> int:
        """Return total endpoint count."""
        cur = self.conn.execute("SELECT COUNT(*) FROM endpoints")
        return cur.fetchone()[0]

    # ────── Graph queries ──────

    def add_edge(self, source_id: str, target_id: str, weight: float, reason: str = "") -> None:
        """Add a weighted edge between two endpoints."""
        self.conn.execute(
            """INSERT OR REPLACE INTO endpoint_edges (source_id, target_id, weight, reason)
               VALUES (?, ?, ?, ?)""",
            (source_id, target_id, weight, reason),
        )
        self.conn.commit()

    def get_neighbors(
        self, ep_id: str, hops: int = 2
    ) -> List[Tuple["EndpointNode", float]]:
        """BFS neighbors up to `hops` distance. Returns (node, combined_weight) pairs."""
        visited: Dict[str, float] = {ep_id: 1.0}
        frontier = {ep_id}
        for _ in range(hops):
            if not frontier:
                break
            placeholders = ",".join("?" * len(frontier))
            cur = self.conn.execute(
                f"""SELECT target_id, weight FROM endpoint_edges
                    WHERE source_id IN ({placeholders})""",
                list(frontier),
            )
            new_frontier: set[str] = set()
            for row in cur.fetchall():
                tid, w = row[0], row[1]
                if tid not in visited:
                    visited[tid] = w
                    new_frontier.add(tid)
                else:
                    visited[tid] = max(visited[tid], w)
            frontier = new_frontier
        result: List[Tuple[EndpointNode, float]] = []
        for nid, weight in visited.items():
            if nid == ep_id:
                continue
            node = self.get_endpoint(nid)
            if node:
                result.append((node, weight))
        return result

    def find_chains(
        self, source_ep_id: str, max_depth: int = 4
    ) -> List[List[str]]:
        """Find all chains from source_ep_id up to max_depth via DFS."""
        chains: List[List[str]] = []

        def _dfs(current: str, path: list[str]) -> None:
            if len(path) > max_depth:
                return
            cur = self.conn.execute(
                "SELECT target_id FROM endpoint_edges WHERE source_id = ?",
                (current,),
            )
            targets = [row[0] for row in cur.fetchall()]
            if not targets:
                if len(path) > 1:
                    chains.append(list(path))
                return
            for tid in targets:
                if tid in path:
                    continue
                path.append(tid)
                _dfs(tid, path)
                path.pop()
            if len(path) > 1:
                chains.append(list(path))

        _dfs(source_ep_id, [source_ep_id])
        return chains

    def similarity(self, ep_a: EndpointNode, ep_b: EndpointNode) -> float:
        """Compute similarity score between two endpoints (0-1)."""
        ref_a = ep_a.path_template or ep_a.url
        ref_b = ep_b.path_template or ep_b.url
        toks_a = set(ref_a.replace("/", " ").replace(".", " ").split())
        toks_b = set(ref_b.replace("/", " ").replace(".", " ").split())
        if toks_a or toks_b:
            union = toks_a | toks_b
            path_jacc = len(toks_a & toks_b) / len(union) if union else 0.0
        else:
            path_jacc = 0.0

        method_match = 0.3 if ep_a.method.upper() == ep_b.method.upper() else 0.0

        params_a = {p.get("name", "") if isinstance(p, dict) else str(p) for p in ep_a.parameters}
        params_b = {p.get("name", "") if isinstance(p, dict) else str(p) for p in ep_b.parameters}
        params_a.discard("")
        params_b.discard("")
        if params_a or params_b:
            p_union = params_a | params_b
            param_jacc = len(params_a & params_b) / len(p_union) if p_union else 0.0
        else:
            param_jacc = 0.0

        return 0.5 * path_jacc + method_match + 0.2 * param_jacc

    # ────── Full-text search ──────

    def search(self, query: str) -> List[EndpointNode]:
        """Full-text search across url, method, sensitivity, tags."""
        cur = self.conn.execute(
            """SELECT e.* FROM endpoints e
               JOIN endpoints_fts f ON e.rowid = f.rowid
               WHERE endpoints_fts MATCH ?""",
            (query,),
        )
        return [_row_to_node(r) for r in cur.fetchall()]

    def stats(self) -> Dict[str, Any]:
        """Return basic statistics."""
        cur = self.conn.execute("SELECT COUNT(*) FROM endpoints")
        ep_count = cur.fetchone()[0]
        cur = self.conn.execute("SELECT COUNT(*) FROM endpoint_edges")
        edge_count = cur.fetchone()[0]
        cur = self.conn.execute(
            "SELECT method, COUNT(*) FROM endpoints GROUP BY method"
        )
        by_method = {row[0]: row[1] for row in cur.fetchall()}
        cur = self.conn.execute(
            "SELECT sensitivity, COUNT(*) FROM endpoints GROUP BY sensitivity"
        )
        by_sensitivity = {row[0]: row[1] for row in cur.fetchall()}
        return {
            "endpoints": ep_count,
            "edges": edge_count,
            "by_method": by_method,
            "by_sensitivity": by_sensitivity,
        }
