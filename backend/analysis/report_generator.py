import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch


def generate_pdf_report(analysis_data: dict, original_filename: str) -> str:
    """
    Generate a professional PDF forensic report.
    Returns the report filename (not the full path).
    """
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # Sanitise filename
    safe_name = original_filename.replace("/", "_").replace("\\", "_")
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{safe_name}_{ts}_report.pdf"
    report_path = os.path.join(reports_dir, report_filename)

    doc = SimpleDocTemplate(
        report_path,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    style_title = ParagraphStyle(
        "TraceTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#00d4ff"),
        spaceAfter=4,
    )
    style_subtitle = ParagraphStyle(
        "TraceSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#888888"),
        alignment=TA_CENTER,
        spaceAfter=16,
    )
    style_h2 = ParagraphStyle(
        "TraceH2",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#00d4ff"),
        spaceBefore=12,
        spaceAfter=6,
    )
    style_body = styles["Normal"]
    style_mono = ParagraphStyle(
        "TraceMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#cccccc"),
        backColor=colors.HexColor("#111111"),
        spaceAfter=2,
    )

    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("TRACE Memory Forensics", style_title))
    story.append(Paragraph("Threat Response &amp; Analysis Cyber Engine — Forensic Report", style_subtitle))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#00d4ff"), spaceAfter=12))

    # ── Executive Summary Table ───────────────────────────────────────────────
    severity = analysis_data.get("severity", "UNKNOWN")
    sev_color_map = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#44ff88",
    }
    sev_color = sev_color_map.get(severity, "#888888")

    meta_data = [
        ["Field", "Value"],
        ["File Analyzed", original_filename],
        ["SHA-256 Hash", analysis_data.get("file_hash", "N/A")],
        ["Detected OS", str(analysis_data.get("detected_os", "N/A")).capitalize()],
        ["Architecture", analysis_data.get("architecture", "N/A")],
        ["File Type", analysis_data.get("file_type_label", "Memory Image")],
        ["File Size", f"{analysis_data.get('file_size_mb', 0)} MB"],
        ["Scan Started", analysis_data.get("timestamps", {}).get("scan_start", "N/A")],
        ["Scan Completed", analysis_data.get("timestamps", {}).get("scan_end", "N/A")],
        ["Threat Score", f"{analysis_data.get('threat_score', 0)} / 100"],
        ["Severity Level", severity],
        ["Analysis Mode", str(analysis_data.get("analysis_mode", "volatility")).upper()],
    ]
    meta_table = Table(meta_data, colWidths=[2.2 * inch, 4.8 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#0a1628")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.HexColor("#00d4ff")),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 10),
        ("BACKGROUND",   (0, 1), (0, -1), colors.HexColor("#050d1a")),
        ("FONTNAME",     (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 1), (-1, -1), 9),
        ("TEXTCOLOR",    (0, 1), (0, -1), colors.HexColor("#aaaaaa")),
        ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#1a2a3a")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0a1628"), colors.HexColor("#060e1c")]),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # ── AI Analyst Summary ────────────────────────────────────────────────────
    story.append(Paragraph("AI Analyst Summary", style_h2))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#1a2a3a"), spaceAfter=8))
    summary = analysis_data.get("forensic_summary", "No summary available.")
    story.append(Paragraph(summary, style_body))
    story.append(Spacer(1, 12))

    # ── Helper: build a section table ────────────────────────────────────────
    def build_section(title: str, items: list, col_header: str, empty_msg: str):
        story.append(Paragraph(title, style_h2))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#1a2a3a"), spaceAfter=8))
        if items:
            rows = [[col_header]] + [[str(item)] for item in items]
            t = Table(rows, colWidths=[7 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#0a1628")),
                ("TEXTCOLOR",    (0, 0), (-1, 0), colors.HexColor("#00d4ff")),
                ("FONTNAME",     (0, 0), (-1, 0), "Courier-Bold"),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("FONTNAME",     (0, 1), (-1, -1), "Courier"),
                ("TEXTCOLOR",    (0, 1), (-1, -1), colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#060e1c"), colors.HexColor("#0a1628")]),
                ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#1a2a3a")),
                ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ]))
            story.append(t)
        else:
            story.append(Paragraph(f"<i>{empty_msg}</i>", style_body))
        story.append(Spacer(1, 12))

    build_section("Malware Indicators", analysis_data.get("malware_indicators", []),
                  "Indicator", "No critical indicators detected.")
    build_section("Suspicious Processes", analysis_data.get("suspicious_processes", []),
                  "Process Name", "Process tree clean.")
    build_section("Hidden / DKOM Processes", analysis_data.get("hidden_processes", []),
                  "Process", "No hidden processes found.")
    build_section("DLL Injection / Malfind", analysis_data.get("dll_injections", []),
                  "Process @ Address", "No code injection detected.")
    build_section("Network Connections", analysis_data.get("network_connections", []),
                  "Connection", "No malicious external connections detected.")
    build_section("Registry Persistence", analysis_data.get("registry_anomalies", []),
                  "Registry Key", "No suspicious autoruns found.")
    build_section("Remediation & Action Plan", analysis_data.get("recommendations", []),
                  "Action Item", "Standard security monitoring protocols apply.")

    # ── IOC List ──────────────────────────────────────────────────────────────
    build_section("Indicators of Compromise (IOC)", analysis_data.get("ioc_list", []),
                  "IOC", "No IOCs extracted.")

    # ── Timeline ──────────────────────────────────────────────────────────────
    timeline = analysis_data.get("timeline", [])
    story.append(Paragraph("Forensic Event Timeline", style_h2))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#1a2a3a"), spaceAfter=8))
    if timeline:
        rows = [["Timestamp", "Event"]]
        for entry in timeline:
            if isinstance(entry, dict):
                rows.append([entry.get("timestamp", ""), entry.get("event", "")])
            else:
                rows.append(["", str(entry)])
        t = Table(rows, colWidths=[2 * inch, 5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#0a1628")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.HexColor("#00d4ff")),
            ("FONTNAME",     (0, 0), (-1, 0), "Courier-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 8),
            ("FONTNAME",     (0, 1), (-1, -1), "Courier"),
            ("TEXTCOLOR",    (0, 1), (-1, -1), colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#060e1c"), colors.HexColor("#0a1628")]),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#1a2a3a")),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("<i>No timeline events recorded.</i>", style_body))
    story.append(Spacer(1, 16))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a2a3a"), spaceAfter=6))
    story.append(Paragraph(
        f"Generated by TRACE Memory Forensics Engine &bull; {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC &bull; CONFIDENTIAL",
        ParagraphStyle("footer", parent=styles["Normal"], fontSize=7,
                       textColor=colors.HexColor("#444444"), alignment=TA_CENTER),
    ))

    doc.build(story)
    return report_filename
