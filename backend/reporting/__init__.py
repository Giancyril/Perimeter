"""
Phase 5: Evidence-Linked Report Generation module.

Exports:
    build_report   — assembles IncidentReport from InvestigationState
    render_markdown — renders report to Markdown string
    render_pdf     — renders report to PDF bytes (requires reportlab)
"""
from backend.reporting.builder import build_report
from backend.reporting.markdown import render_markdown
from backend.reporting.pdf import render_pdf
from backend.reporting.models import IncidentReport, TimelineEvent, EntityTraceability

__all__ = [
    "build_report",
    "render_markdown",
    "render_pdf",
    "IncidentReport",
    "TimelineEvent",
    "EntityTraceability",
]
