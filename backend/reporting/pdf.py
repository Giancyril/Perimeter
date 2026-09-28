"""
Phase 5: PDF Report Renderer.

Converts a structured IncidentReport into a professional PDF document
using reportlab. Falls back gracefully if reportlab is not installed.
"""
from __future__ import annotations

import io
from typing import Optional

from backend.reporting.models import IncidentReport

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False


_SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#2563EB"),
    "informational": colors.HexColor("#6B7280"),
}


def render_pdf(report: IncidentReport) -> bytes:
    """
    Render the incident report as PDF bytes.

    Returns:
        Raw PDF bytes, or raises RuntimeError if reportlab is unavailable.
    """
    if not _REPORTLAB_AVAILABLE:
        raise RuntimeError(
            "PDF generation requires reportlab. "
            "Install it with: pip install reportlab"
        )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    style_normal = styles["Normal"]
    style_h1 = styles["Heading1"]
    style_h2 = styles["Heading2"]
    style_h3 = styles["Heading3"]
    style_code = ParagraphStyle(
        "Code",
        parent=style_normal,
        fontName="Courier",
        fontSize=8,
        backColor=colors.HexColor("#F3F4F6"),
        leading=12,
    )

    sev = report.final_severity.value
    floor = report.deterministic_floor.value
    sev_color = _SEVERITY_COLORS.get(sev, colors.grey)

    story = []

    # ---- Title ----
    story.append(Paragraph(
        f"<font color=\'#{sev_color.hexval()[2:]}\'>"
        f"Security Incident Report</font>",
        style_h1,
    ))
    story.append(Paragraph(f"Incident: {report.incident_id}", style_h2))
    story.append(Spacer(1, 0.3 * cm))

    meta_data = [
        ["Report ID", report.report_id],
        ["Generated", report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Status", report.status.upper()],
        ["Final Severity", sev.upper()],
        ["Deterministic Floor", floor.upper()],
    ]
    meta_table = Table(meta_data, colWidths=[5 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("TEXTCOLOR", (1, 3), (1, 3), sev_color),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=sev_color))
    story.append(Spacer(1, 0.3 * cm))

    # ---- Severity Audit ----
    story.append(Paragraph("Severity Determination", style_h2))
    audit = report.severity_audit
    audit_data = [
        ["Metric", "Value"],
        ["Base Score", str(audit.base_score)],
        ["Asset Multiplier", f"{audit.asset_multiplier}x"],
        ["Threat Intel Points", f"+{audit.threat_intel_points}"],
        ["MITRE Multiplier", f"{audit.mitre_multiplier}x"],
        ["Lateral Movement Points", f"+{audit.lateral_movement_points}"],
        ["Composite Raw Score", str(audit.raw_calculated_score)],
        ["Rule Override", audit.rule_override_reason or "None"],
        ["Floor Enforced", "YES (LLM downgrade blocked)" if audit.floor_enforced else "No"],
    ]
    audit_table = Table(audit_data, colWidths=[7 * cm, 10 * cm])
    audit_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.append(audit_table)
    story.append(Spacer(1, 0.5 * cm))

    # ---- MITRE ATT&CK ----
    story.append(Paragraph("MITRE ATT&CK Mapping", style_h2))
    story.append(Paragraph(
        f"Tactics ({len(report.mitre_tactics)}): "
        + (", ".join(report.mitre_tactics) or "None identified"),
        style_normal,
    ))
    story.append(Paragraph(
        "Techniques: " + (", ".join(report.mitre_techniques) or "None identified"),
        style_normal,
    ))
    story.append(Paragraph(
        f"Attack Chain Span: {report.attack_chain_span} stage(s)", style_normal
    ))
    story.append(Spacer(1, 0.4 * cm))

    # ---- Entity Traceability ----
    story.append(Paragraph("Affected Entities", style_h2))
    ent_data = [["Entity", "Type", "Criticality", "TI Verdict", "Abuse Score", "Events"]]
    for ent in report.entities:
        ent_data.append([
            ent.entity_value,
            ent.entity_type,
            ent.criticality or "—",
            ent.threat_verdict or "unknown",
            str(ent.abuse_score) if ent.abuse_score is not None else "—",
            str(len(ent.timeline_event_indices)),
        ])
    ent_table = Table(ent_data, colWidths=[4.5 * cm, 2 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm, 2 * cm])
    ent_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ("PADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.append(ent_table)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Timeline (abbreviated to first 15 events for PDF) ----
    story.append(Paragraph(
        f"Evidence Timeline ({len(report.timeline)} events)", style_h2
    ))
    for i, ev in enumerate(report.timeline[:15], 1):
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        entities_str = ", ".join(ev.related_entities) if ev.related_entities else "—"
        block = [
            Paragraph(f"[{i}] {ev.title}", style_h3),
            Paragraph(f"Time: {ts} | Type: {ev.event_type} | Source: {ev.source}", style_normal),
            Paragraph(f"Entities: {entities_str}", style_normal),
            Paragraph(ev.description, style_code),
        ]
        if ev.severity_impact:
            block.append(Paragraph(f"Severity Impact: {ev.severity_impact}", style_normal))
        block.append(Spacer(1, 0.2 * cm))
        story.append(KeepTogether(block))

    if len(report.timeline) > 15:
        story.append(Paragraph(
            f"... {len(report.timeline) - 15} additional events truncated in PDF. "
            "See Markdown report for full timeline.",
            style_normal,
        ))

    # ---- Recommended Actions ----
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Paragraph("Recommended Containment Actions", style_h2))
    for i, action in enumerate(report.recommended_actions, 1):
        story.append(Paragraph(f"{i}. {action}", style_normal))

    # ---- Footer ----
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Paragraph(
        f"Report ID: {report.report_id} | Incident: {report.incident_id} | "
        f"Generated: {report.generated_at.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        ParagraphStyle("Footer", parent=style_normal, fontSize=7, textColor=colors.grey),
    ))
    story.append(Paragraph(
        "This report was auto-generated by the Security Operations Agent. "
        "Severity floors are deterministically enforced and cannot be downgraded by LLM reasoning.",
        ParagraphStyle("Disclaimer", parent=style_normal, fontSize=7, textColor=colors.grey),
    ))

    doc.build(story)
    return buf.getvalue()
