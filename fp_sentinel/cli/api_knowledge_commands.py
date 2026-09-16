"""API Knowledge Graph CLI commands.

Subcommands: import-json, import-har, import-burp, stats, export-schema,
export-har, attack-surface, viz
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

import typer

from ..api_knowledge.store import ApiKnowledgeStore, EndpointNode
from ..api_knowledge.schema_infer import SchemaInferer
from ..api_knowledge.associator import ApiAssociator
from ..api_knowledge.exporter import build_openapi_spec, build_har, export_to_json


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="api-knowledge",
        description="API Knowledge Graph — schema inference + relationship analysis + visualization",
    )
    sub = parser.add_subsers(dest="command", required=True)

    # import-json
    p_imp = sub.add_parser("import-json", help="Import endpoints from JSON file")
    p_imp.add_argument("--file", required=True, help="JSON file path")
    p_imp.add_argument("--db", default=None, help="Database path")

    # import-har
    p_har = sub.add_parser("import-har", help="Import endpoints from HAR file")
    p_har.add_argument("--file", required=True, help="HAR file path")
    p_har.add_argument("--db", default=None, help="Database path")

    # import-burp
    p_burp = sub.add_parser("import-burp", help="Import endpoints from Burp Suite export")
    p_burp.add_argument("--file", required=True, help="Burp XML/JSON file path")
    p_burp.add_argument("--db", default=None, help="Database path")

    # stats
    sub.add_parser("stats", help="Show database statistics")

    # export-schema
    p_exp = sub.add_parser("export-schema", help="Export OpenAPI 3.0 schema")
    p_exp.add_argument("--output", default="-")
    p_exp.add_argument("--db", default=None)

    # export-har
    p_har_exp = sub.add_parser("export-har", help="Export endpoints as HAR 1.2")
    p_har_exp.add_argument("--output", default="-")
    p_har_exp.add_argument("--db", default=None)

    # attack-surface
    p_atk = sub.add_parser("attack-surface", help="Discover attack surface (BOLA/IDOR)")
    p_atk.add_argument("--db", default=None)
    p_atk.add_argument("--link", action="store_true", help="Auto-link endpoints before analysis")
    p_atk.add_argument("--output", default="-")
    p_atk.add_argument("--format", choices=["json", "markdown"], default="markdown")

    # viz
    p_viz = sub.add_parser("viz", help="Generate D3 visualization HTML")
    p_viz.add_argument("--output", default="api_knowledge_graph.html")
    p_viz.add_argument("--db", default=None)
    p_viz.add_argument("--format", choices=["html", "json"], default="html")
    p_viz.add_argument("--group-by", choices=["prefix", "tag", "schema"], default=None)

    return parser


def _import_json(args: argparse.Namespace) -> int:
    """Import endpoints from a JSON samples file."""
    path = Path(args.file)
    if not path.is_file():
        print(f"File not found: {path}", file=sys.stderr)
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("endpoints", [])
    store = ApiKnowledgeStore(db_path=args.db)
    store.open()
    try:
        inferer = SchemaInferer()
        for ep in items:
            req_samples = ep.get("request_samples") or ep.get("requests") or []
            resp_samples = ep.get("response_samples") or ep.get("responses") or []
            if req_samples or resp_samples:
                inferred = inferer.infer_from_samples(
                    ep.get("method", "GET"),
                    ep.get("url", ep.get("path", "")),
                    request_samples=req_samples or None,
                    response_samples=resp_samples or None,
                )
                path_item = list(inferred.get("paths", {}).keys())
                req_body_schema = None
                resp_schemas = {}
                if path_item:
                    ops = inferred["paths"][path_item[0]]
                    method_key = list(ops.keys())[0] if ops else "get"
                    op = ops.get(method_key, {})
                    rb = op.get("requestBody", {})
                    if rb.get("content", {}).get("application/json", {}).get("schema"):
                        req_body_schema = rb["content"]["application/json"]["schema"]
                    for code, resp in op.get("responses", {}).items():
                        try:
                            sc = int(code)
                            schema = resp.get("content", {}).get("application/json", {}).get("schema")
                            if schema:
                                resp_schemas[sc] = schema
                        except (ValueError, TypeError):
                            pass
            else:
                req_body_schema = None
                resp_schemas = {}
            node = EndpointNode(
                url=ep.get("url", ep.get("path", "")),
                method=ep.get("method", "GET"),
                path_template=ep.get("path_template", ""),
                parameters=ep.get("parameters", []),
                request_schema=req_body_schema or ep.get("request_schema"),
                response_schemas=ep.get("response_schemas") or resp_schemas,
                sensitivity=ep.get("sensitivity", "medium"),
                source=ep.get("source", "import"),
                tags=ep.get("tags", []),
                references=ep.get("references", []),
            )
            store.add_endpoint(node)
        print(f"Imported {len(items)} endpoints.", file=sys.stderr)
    finally:
        store.close()
    return 0


def _import_har(args: argparse.Namespace) -> int:
    """Import endpoints from a HAR file."""
    from fp_sentinel.web_api.api_discovery import ApiDiscovery
    endpoints = ApiDiscovery.from_har(args.file)
    store = ApiKnowledgeStore(db_path=args.db)
    store.open()
    try:
        for ep in endpoints:
            node = EndpointNode(
                url=ep.url,
                method=ep.method,
                sensitivity="medium",
                source="har",
                tags=["imported"],
            )
            store.add_endpoint(node)
        print(f"Imported {len(endpoints)} endpoints from HAR.", file=sys.stderr)
    finally:
        store.close()
    return 0


def _import_burp(args: argparse.Namespace) -> int:
    """Import endpoints from a Burp Suite export."""
    from fp_sentinel.web_api.api_discovery import ApiDiscovery
    endpoints = ApiDiscovery.from_burp(args.file)
    store = ApiKnowledgeStore(db_path=args.db)
    store.open()
    try:
        for ep in endpoints:
            node = EndpointNode(
                url=ep.url,
                method=ep.method,
                sensitivity="medium",
                source="burp",
                tags=["imported"],
            )
            store.add_endpoint(node)
        print(f"Imported {len(endpoints)} endpoints from Burp.", file=sys.stderr)
    finally:
        store.close()
    return 0


def _stats(args: argparse.Namespace) -> int:
    """Print database statistics."""
    store = ApiKnowledgeStore(db_path=args.db)
    store.open()
    try:
        stats = store.stats()
        assoc = ApiAssociator()
        islands = assoc.find_islands(store)
        stats["islands"] = len(islands)
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    finally:
        store.close()
    return 0


def _export_schema(args: argparse.Namespace) -> int:
    """Export OpenAPI 3.0 schema."""
    store = ApiKnowledgeStore(db_path=args.db)
    store.open()
    try:
        eps = store.all_endpoints()
        result = build_openapi_spec(eps)
        out = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output and args.output != "-":
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"Written: {args.output}", file=sys.stderr)
        else:
            print(out)
    finally:
        store.close()
    return 0


def _export_har(args: argparse.Namespace) -> int:
    """Export endpoints as HAR 1.2."""
    store = ApiKnowledgeStore(db_path=args.db)
    store.open()
    try:
        eps = store.all_endpoints()
        result = build_har(eps)
        out = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output and args.output != "-":
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"Written: {args.output}", file=sys.stderr)
        else:
            print(out)
    finally:
        store.close()
    return 0


def _attack_surface(args: argparse.Namespace) -> int:
    """Run attack surface discovery."""
    store = ApiKnowledgeStore(db_path=args.db)
    store.open()
    try:
        assoc = ApiAssociator()
        if args.link:
            assoc.link_endpoints(store)
        if args.format == "markdown":
            report = assoc.build_attack_surface_report(store)
            out = report
        else:
            bottlenecks = assoc.find_bottlenecks(store)
            islands = assoc.find_islands(store)
            bola = assoc.find_horizontal_attack_surface(store)
            result = {
                "bottlenecks": [{"endpoint_id": eid, "in_degree": deg} for eid, deg in bottlenecks],
                "island_count": len(islands),
                "largest_island": max(len(c) for c in islands) if islands else 0,
                "bola_risks": bola,
            }
            out = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output and args.output != "-":
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"Written: {args.output}", file=sys.stderr)
        else:
            print(out)
    finally:
        store.close()
    return 0


def _viz(args: argparse.Namespace) -> int:
    """Generate D3 visualization."""
    from ..api_knowledge.visualize import main as viz_main
    argv = ["--output", args.output, "--format", args.format]
    if args.db:
        argv += ["--db", args.db]
    if args.group_by:
        argv += ["--group-by", args.group_by]
    return viz_main(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Standalone CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "import-json": _import_json,
        "import-har": _import_har,
        "import-burp": _import_burp,
        "stats": _stats,
        "export-schema": _export_schema,
        "export-har": _export_har,
        "attack-surface": _attack_surface,
        "viz": _viz,
    }
    return handlers[args.command](args)


# ── Typer app (for xuanjian CLI integration) ──
try:
    api_knowledge_app = typer.Typer(
        name="api-knowledge",
        help="API Knowledge Graph (GraphRAG-style): schema inference + relationship analysis",
        no_args_is_help=True,
    )

    @api_knowledge_app.command("import-json")
    def _imp_json(
        file: str = typer.Option(..., "--file"),
        db: Optional[str] = typer.Option(None, "--db"),
    ):
        raise typer.Exit(_import_json(argparse.Namespace(file=file, db=db)))

    @api_knowledge_app.command("import-har")
    def _imp_har(
        file: str = typer.Option(..., "--file"),
        db: Optional[str] = typer.Option(None, "--db"),
    ):
        raise typer.Exit(_import_har(argparse.Namespace(file=file, db=db)))

    @api_knowledge_app.command("import-burp")
    def _imp_burp(
        file: str = typer.Option(..., "--file"),
        db: Optional[str] = typer.Option(None, "--db"),
    ):
        raise typer.Exit(_import_burp(argparse.Namespace(file=file, db=db)))

    @api_knowledge_app.command("stats")
    def _stats_cmd(db: Optional[str] = typer.Option(None, "--db")):
        raise typer.Exit(_stats(argparse.Namespace(db=db)))

    @api_knowledge_app.command("export-schema")
    def _exp_cmd(
        output: str = typer.Option("-", "--output"),
        db: Optional[str] = typer.Option(None, "--db"),
    ):
        raise typer.Exit(_export_schema(argparse.Namespace(output=output, db=db)))

    @api_knowledge_app.command("export-har")
    def _exp_har_cmd(
        output: str = typer.Option("-", "--output"),
        db: Optional[str] = typer.Option(None, "--db"),
    ):
        raise typer.Exit(_export_har(argparse.Namespace(output=output, db=db)))

    @api_knowledge_app.command("attack-surface")
    def _atk_cmd(
        db: Optional[str] = typer.Option(None, "--db"),
        link: bool = typer.Option(False, "--link"),
        output: str = typer.Option("-", "--output"),
        format: str = typer.Option("markdown", "--format"),
    ):
        raise typer.Exit(_attack_surface(argparse.Namespace(db=db, link=link, output=output, format=format)))

    @api_knowledge_app.command("viz")
    def _viz_cmd(
        output: str = typer.Option("api_knowledge_graph.html", "--output"),
        db: Optional[str] = typer.Option(None, "--db"),
        format: str = typer.Option("html", "--format"),
        group_by: Optional[str] = typer.Option(None, "--group-by"),
    ):
        raise typer.Exit(_viz(argparse.Namespace(output=output, db=db, format=format, group_by=group_by)))

except ImportError:
    api_knowledge_app = None  # type: ignore[assignment]


if __name__ == "__main__":
    sys.exit(main())
