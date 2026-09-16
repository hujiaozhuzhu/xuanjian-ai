"""D3 force-directed API knowledge graph visualization.

Outputs self-contained HTML (D3.js from CDN + inline JSON data) or raw graph JSON.
Usable as both a library (`render_html`) and a CLI script.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from .store import ApiKnowledgeStore, EndpointNode


# Method -> color mapping
_METHOD_COLORS: dict[str, str] = {
    "GET": "#4caf50",
    "POST": "#2196f3",
    "PUT": "#ff9800",
    "DELETE": "#f44336",
    "PATCH": "#9c27b0",
}

# Sensitivity -> radius
_SENSITIVITY_RADIUS: dict[str, int] = {
    "CRITICAL": 18,
    "HIGH": 14,
    "medium": 10,
    "low": 7,
}


def _graph_data(store: ApiKnowledgeStore) -> dict:
    """Build graph JSON structure from store."""
    eps = store.all_endpoints()
    nodes: list[dict] = []
    id_set: set[str] = set()
    for ep in eps:
        id_set.add(ep.id)
        radius = _SENSITIVITY_RADIUS.get(ep.sensitivity, 10)
        color = _METHOD_COLORS.get(ep.method.upper(), "#9e9e9e")
        nodes.append(
            {
                "id": ep.id,
                "url": ep.url,
                "method": ep.method.upper(),
                "sensitivity": ep.sensitivity,
                "source": ep.source,
                "tags": ep.tags,
                "radius": radius,
                "color": color,
            }
        )
    cur = store.conn.execute(
        "SELECT source_id, target_id, weight, reason FROM endpoint_edges"
    )
    links: list[dict] = []
    for row in cur.fetchall():
        src, tgt, w, reason = row[0], row[1], row[2], row[3]
        if src in id_set and tgt in id_set:
            links.append(
                {"source": src, "target": tgt, "weight": w, "reason": reason}
            )
    return {"nodes": nodes, "links": links}


def render_html(store: ApiKnowledgeStore) -> str:
    """Render a self-contained D3 force-directed graph as HTML string."""
    data = _graph_data(store)
    data_json = json.dumps(data, ensure_ascii=False)

    legend_items = "".join(
        f'<span style="display:inline-flex;align-items:center;margin-right:12px;">'
        f'<span style="width:12px;height:12px;border-radius:50%;background:{c};display:inline-block;margin-right:4px;"></span>'
        f'{m}</span>'
        for m, c in sorted(_METHOD_COLORS.items())
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Knowledge Graph</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: system-ui, sans-serif; background: #1a1a2e; color: #eee; overflow: hidden; }}
#app {{ display: flex; height: 100vh; }}
#sidebar {{ width: 320px; background: #16213e; padding: 16px; overflow-y: auto; border-right: 1px solid #0f3460; flex-shrink: 0; }}
#sidebar h2 {{ margin-bottom: 12px; font-size: 16px; color: #e94560; }}
#sidebar input[type=search] {{ width: 100%; padding: 8px; border-radius: 4px; border: none; background: #0f3460; color: #eee; box-sizing: border-box; }}
.detail-row {{ margin: 8px 0; font-size: 13px; word-break: break-all; }}
.detail-label {{ color: #aaa; font-size: 11px; display: block; margin-bottom: 2px; }}
#canvas {{ flex: 1; position: relative; }}
svg {{ width: 100%; height: 100%; cursor: grab; }}
.link {{ stroke: #4a5568; stroke-opacity: 0.6; }}
.node circle {{ stroke: #fff; stroke-width: 1.5px; cursor: pointer; }}
.node text {{ fill: #ddd; font-size: 10px; pointer-events: none; }}
#status {{ position: absolute; bottom: 8px; left: 16px; font-size: 12px; color: #aaa; }}
#legend {{ position: absolute; top: 8px; right: 16px; background: rgba(22,33,62,0.9); padding: 8px 12px; border-radius: 6px; font-size: 12px; }}
</style>
</head>
<body>
<div id="app">
  <div id="sidebar">
    <h2>API Knowledge Graph</h2>
    <input type="search" id="search" placeholder="Search endpoint..." oninput="doSearch(this.value)">
    <div id="detail">
      <div class="detail-row"><span class="detail-label">Click a node to see details</span></div>
    </div>
  </div>
  <div id="canvas">
    <svg id="graph"></svg>
    <div id="legend">{legend_items}</div>
    <div id="status">Loading...</div>
  </div>
</div>
<script>
const DATA = {data_json};

const svg = d3.select("#graph");
const container = document.getElementById("canvas");
const statusEl = document.getElementById("status");
let width = container.clientWidth, height = container.clientHeight;

svg.attr("viewBox", `0 0 ${{width}} ${{height}}`);

const g = svg.append("g");

// Zoom / pan
const zoom = d3.zoom()
  .scaleExtent([0.1, 8])
  .on("zoom", (event) => g.attr("transform", event.transform));
svg.call(zoom);

// Build node/link maps
const nodeMap = Object.fromEntries(DATA.nodes.map(n => [n.id, n]));
const links = DATA.links.map(d => ({{ source: d.source, target: d.target, weight: d.weight, reason: d.reason }}));
const nodes = DATA.nodes.map(d => ({{...d, x: width/2 + (Math.random()-0.5)*300, y: height/2 + (Math.random()-0.5)*300}}));

// Force simulation
const simulation = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d => d.id).distance(100))
  .force("charge", d3.forceManyBody().strength(-200))
  .force("center", d3.forceCenter(width / 2, height / 2))
  .force("collision", d3.forceCollide().radius(d => d.radius + 5));

// Render links
const link = g.append("g")
  .selectAll("line")
  .data(links)
  .join("line")
  .attr("class", "link")
  .attr("stroke-width", d => Math.max(1, (d.weight || 0.5) * 3));

// Render nodes
const node = g.append("g")
  .selectAll("g")
  .data(nodes)
  .join("g")
  .attr("class", "node")
  .call(d3.drag()
    .on("start", (event, d) => {{ if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
    .on("drag", (event, d) => {{ d.fx = event.x; d.fy = event.y; }})
    .on("end", (event, d) => {{ if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }}));

node.append("circle")
  .attr("r", d => d.radius)
  .attr("fill", d => d.color);

node.append("text")
  .attr("x", d => d.radius + 3)
  .attr("y", 4)
  .text(d => d.method + " " + (d.url.length > 30 ? d.url.slice(0, 27) + "..." : d.url));

node.on("click", (event, d) => showDetail(d));

function showDetail(n) {{
  const detailEl = document.getElementById("detail");
  const tags = (n.tags || []).join(", ") || "-";
  detailEl.innerHTML = `
    <div class="detail-row"><span class="detail-label">Method</span><div>${{n.method}}</div></div>
    <div class="detail-row"><span class="detail-label">URL</span><div>${{n.url}}</div></div>
    <div class="detail-row"><span class="detail-label">Sensitivity</span><div>${{n.sensitivity}}</div></div>
    <div class="detail-row"><span class="detail-label">Source</span><div>${{n.source}}</div></div>
    <div class="detail-row"><span class="detail-label">Tags</span><div>${{tags}}</div></div>
  `;
}}

function doSearch(q) {{
  const ql = q.toLowerCase();
  node.style("opacity", d => {{
    return !ql || d.url.toLowerCase().includes(ql) || d.method.toLowerCase().includes(ql) || (d.tags||[]).join(",").toLowerCase().includes(ql) ? 1 : 0.15;
  }});
  link.style("opacity", ql ? 0.15 : 0.6);
}}

simulation.on("tick", () => {{
  link
    .attr("x1", d => d.source.x).attr("y1", d => d.source.y)
    .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
  node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
  statusEl.textContent = `Nodes: ${{nodes.length}} | Edges: ${{links.length}}`;
}});

// Resize handling
window.addEventListener("resize", () => {{
  width = container.clientWidth;
  height = container.clientHeight;
  svg.attr("viewBox", `0 0 ${{width}} ${{height}}`);
  simulation.force("center", d3.forceCenter(width / 2, height / 2));
  simulation.alpha(0.3).restart();
}});
</script>
</body>
</html>"""


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for ``python -m fp_sentinel.api_knowledge.visualize``."""
    parser = argparse.ArgumentParser(prog="api-knowledge-viz")
    parser.add_argument("--db", help="Path to api_knowledge SQLite db")
    parser.add_argument(
        "--output", default="-",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--format", choices=["html", "json"], default="html",
        help="Output format",
    )
    parser.add_argument(
        "--group-by", choices=["prefix", "tag", "schema"], default=None,
        help="Grouping strategy for visualization",
    )
    args = parser.parse_args(argv)

    store = ApiKnowledgeStore(db_path=args.db)
    store.open()
    try:
        if args.format == "json":
            data = _graph_data(store)
            out = json.dumps(data, ensure_ascii=False, indent=2)
        else:
            out = render_html(store)

        if args.output and args.output != "-":
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"Written: {args.output}", file=sys.stderr)
        else:
            print(out)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
