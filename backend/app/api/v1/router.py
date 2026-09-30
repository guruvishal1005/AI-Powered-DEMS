"""API v1 router aggregation."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.routers import (
    admin,
    alerts,
    analysis,
    audit,
    auth,
    cases,
    custody,
    dashboard,
    evidence,
    findings,
    graph,
    intelligence,
    notifications,
    reports,
    timeline,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(cases.router)
api_router.include_router(findings.router)
api_router.include_router(evidence.router)
api_router.include_router(custody.router)
api_router.include_router(timeline.router)
api_router.include_router(graph.router)
api_router.include_router(intelligence.router)
api_router.include_router(analysis.router)
api_router.include_router(alerts.router)
api_router.include_router(notifications.router)
api_router.include_router(reports.router)
api_router.include_router(audit.router)
api_router.include_router(admin.router)
