"""Evidence-Linked Report Generation Package (Day 5 Advanced Architecture)."""
from backend.reporting.models import (
    IncidentReport,
    TimelineEvent,
    EntityTraceability,
    SeverityAuditRecord,
)
from backend.reporting.builder import build_report
from backend.reporting.markdown import render_markdown
from backend.reporting.pdf import render_pdf

# Day 5 Advanced Reporting Modules
from backend.reporting.executive_briefing import (
    ExecutiveBriefing,
    ExecutiveBriefingGenerator,
)
from backend.reporting.stix_exporter import (
    STIX21Exporter,
)
from backend.reporting.attack_graph import (
    AttackGraphVisualizer,
    AttackPathSummary,
)
from backend.reporting.chain_of_custody import (
    EvidenceType,
    EvidenceItem,
    ChainOfCustodyManifest,
    ChainOfCustodyBuilder,
)
from backend.reporting.compliance_engine import (
    RegulatoryObligation,
    BreachComplianceReport,
    ComplianceDisclosureEngine,
)
from backend.reporting.root_cause_analyzer import (
    RemediationAction,
    RootCauseReport,
    RootCauseAnalyzer,
)
from backend.reporting.dispatch import (
    AudienceRole,
    ReportDispatcher,
)
from backend.reporting.report_diff import (
    ReportDiffResult,
    ReportDiffEngine,
)
from backend.reporting.orchestrator import (
    IncidentReportPackage,
    ReportOrchestrator,
    report_orchestrator,
)

__all__ = [
    # Core Models & Renderers
    "IncidentReport",
    "TimelineEvent",
    "EntityTraceability",
    "SeverityAuditRecord",
    "build_report",
    "render_markdown",
    "render_pdf",
    # Executive Briefing
    "ExecutiveBriefing",
    "ExecutiveBriefingGenerator",
    # STIX 2.1
    "STIX21Exporter",
    # Attack Graph Visualizer
    "AttackGraphVisualizer",
    "AttackPathSummary",
    # Chain of Custody
    "EvidenceType",
    "EvidenceItem",
    "ChainOfCustodyManifest",
    "ChainOfCustodyBuilder",
    # Compliance & Breach Disclosures
    "RegulatoryObligation",
    "BreachComplianceReport",
    "ComplianceDisclosureEngine",
    # Root Cause Analysis (RCA)
    "RemediationAction",
    "RootCauseReport",
    "RootCauseAnalyzer",
    # Dispatch & Notification
    "AudienceRole",
    "ReportDispatcher",
    # Report Diff & Revision Tracking
    "ReportDiffResult",
    "ReportDiffEngine",
    # Unified Orchestration
    "IncidentReportPackage",
    "ReportOrchestrator",
    "report_orchestrator",
]
