"""API Knowledge Graph — GraphRAG-style API schema inference + relationship analysis.

Five pipelines:
1. Storage layer    → store.py      (SQLite + FTS5 full-text search)
2. Schema inference → schema_infer.py (OpenAPI 3.0 schema from samples)
3. Association      → associator.py (link endpoints, find attack surface)
4. Visualization    → visualize.py  (D3 force-directed graph, self-contained HTML)
5. Export           → exporter.py   (OpenAPI 3.0.3 + HAR 1.2 builders)
"""

from .store import ApiKnowledgeStore, EndpointNode
from .schema_infer import SchemaInferer
from .associator import ApiAssociator
from .store import available as store_available
from .store import self_check as store_self_check
from .store import module_version as store_module_version
from .associator import available as associator_available
from .associator import self_check as associator_self_check
from .associator import module_version as associator_module_version

__all__ = [
    "ApiKnowledgeStore",
    "EndpointNode",
    "SchemaInferer",
    "ApiAssociator",
    "store_available",
    "store_self_check",
    "store_module_version",
    "associator_available",
    "associator_self_check",
    "associator_module_version",
]
