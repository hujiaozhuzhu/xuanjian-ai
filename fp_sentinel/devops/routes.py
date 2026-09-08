"""
DevSecOps - REST API Routes

Endpoints:
- POST /api/devops/sync
- POST /api/devops/gate
- POST /api/devops/close
- POST /api/devops/link
- GET  /api/devops/mappings
- GET  /api/devops/stats
- POST /api/devops/webhook/{provider}
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from ..database.connection import get_database
from .models import (
    DevOpsProvider,
    PipelineGateRequest,
    SyncFindingsRequest,
    TicketCloseRequest,
    TicketLinkRequest,
)
from .pipeline_gate import evaluate_gate, gate_exit_code
from .repository import FindingTicketMappingRepo, PipelineGateRecordRepo, SyncRecordRepo
from .service import DevOpsService
from .webhook_handler import parse_webhook_event

logger = logging.getLogger(__name__)

devops_router = APIRouter(prefix="/api/devops", tags=["devops"])


def _build_service(db):
    return DevOpsService(
        FindingTicketMappingRepo(db.conn),
        SyncRecordRepo(db.conn),
        PipelineGateRecordRepo(db.conn),
    )


@devops_router.post("/sync")
async def sync_findings(request: SyncFindingsRequest):
    async with get_database() as db:
        service = _build_service(db)
        result = await service.sync_findings(request)
        return result.model_dump()


@devops_router.post("/gate")
async def evaluate_gate(request: PipelineGateRequest):
    async with get_database() as db:
        service = _build_service(db)
        result = await service.evaluate_pipeline_gate(request, persist=True)
        return result.model_dump()


@devops_router.post("/close")
async def close_ticket(request: TicketCloseRequest):
    async with get_database() as db:
        service = _build_service(db)
        record = await service.close_ticket(request)
        return {"status": record.status.value, "ticket_id": request.ticket_id}


@devops_router.post("/link")
async def link_commit(request: TicketLinkRequest):
    async with get_database() as db:
        service = _build_service(db)
        record = await service.link_fix_commit(request)
        return {"status": record.status.value, "ticket_id": request.ticket_id}


@devops_router.get("/mappings")
async def list_mappings(
    provider: Optional[str] = None,
    ticket_status: Optional[str] = None,
    limit: int = 50,
):
    async with get_database() as db:
        repo = FindingTicketMappingRepo(db.conn)
        mappings = await repo.list_mappings(
            provider=provider,
            ticket_status=ticket_status,
            limit=limit,
        )
        return [m.model_dump() for m in mappings]


@devops_router.get("/stats")
async def get_stats():
    async with get_database() as db:
        service = _build_service(db)
        stats = await service.get_stats()
        return stats.model_dump()


@devops_router.get("/mappings/{mapping_id}")
async def get_mapping(mapping_id: str):
    async with get_database() as db:
        repo = FindingTicketMappingRepo(db.conn)
        mapping = await repo.get_by_id(mapping_id)
        if not mapping:
            raise HTTPException(404, "Mapping not found")
        result = mapping.model_dump()
        sync_repo = SyncRecordRepo(db.conn)
        records = await sync_repo.list_by_mapping(mapping_id, limit=20)
        result["sync_records"] = [r.model_dump() for r in records]
        return result


@devops_router.post("/webhook/{provider}")
async def receive_webhook(provider: str, request: Request):
    payload = await request.json()
    headers = request.headers

    provider_enum = DevOpsProvider(provider)
    event_header = ""
    if provider == "gitlab":
        event_header = headers.get("x-gitlab-event", "")
    elif provider == "github":
        event_header = headers.get("x-github-event", "")
    elif provider == "jira":
        event_header = payload.get("webhookEvent", "")

    event_type = parse_webhook_event(provider_enum, event_header, payload)

    async with get_database() as db:
        service = _build_service(db)
        record = await service.handle_webhook_event(
            event_type=event_type,
            provider_value=provider,
            payload=payload,
        )

    return {
        "status": "ok",
        "event_type": event_type.value,
        "provider": provider,
        "sync_record_id": record.id if record else None,
    }
