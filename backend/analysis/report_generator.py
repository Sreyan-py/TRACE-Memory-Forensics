import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(analysis_data, original_filename):
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    reports_dir = os.path.join(BASE_DIR, "reports")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)

    report_filename = f"{original_filename}_report.pdf"
    report_path = os.path.join(reports_dir, report_filename)

    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Title
    story.append(Paragraph(f"TRACE: {analysis_data.get('analysis_type', 'Forensic Analysis')} Report", title_style))
    story.append(Spacer(1, 12))

    # Basic Info
    story.append(Paragraph(f"<b>File Analyzed:</b> {original_filename}", normal_style))
    story.append(Paragraph(f"<b>Scan Timestamp:</b> {analysis_data['timestamps']['scan_end']}", normal_style))
    
    severity = analysis_data.get('severity', 'UNKNOWN')
    severity_color = "<font color='red'>" if severity in ['HIGH', 'CRITICAL'] else "<font color='orange'>" if severity == 'MEDIUM' else "<font color='green'>"
    story.append(Paragraph(f"<b>Threat Score:</b> {severity_color}{analysis_data.get('threat_score', 0)}/100</font>", normal_style))
    story.append(Paragraph(f"<b>Severity Level:</b> {severity_color}{severity}</font>", normal_style))
    story.append(Spacer(1, 24))

    # AI Summary
    story.append(Paragraph("AI-Assisted Forensic Summary", heading_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<i>{analysis_data.get('forensic_summary', 'No summary available.')}</i>", normal_style))
    story.append(Spacer(1, 24))

    # Helper function for tables
    def build_table(title, data_list, col_title, bg_color):
        story.append(Paragraph(title, heading_style))
        story.append(Spacer(1, 12))
        if data_list:
            table_data = [[col_title]]
            for item in data_list:
                table_data.append([item])
            t = Table(table_data, colWidths=[450])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0b1020")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor(bg_color)),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(t)
        else:
            story.append(Paragraph(f"No {title.lower()} detected.", normal_style))
        story.append(Spacer(1, 24))

    # Build sections
    build_table("Malware Indicators", analysis_data.get('malware_indicators', []), "Indicator Details", "#ffebee")
    build_table("Suspicious Processes", analysis_data.get('suspicious_processes', []), "Process Name", "#fff3e0")
    build_table("Hidden Processes", analysis_data.get('hidden_processes', []), "Process Name", "#ffebee")
    build_table("DLL Injections", analysis_data.get('dll_injections', []), "DLL Name", "#ffebee")
    build_table("Network Connections", analysis_data.get('network_connections', []), "Connection String", "#e3f2fd")
    build_table("Registry Anomalies", analysis_data.get('registry_anomalies', []), "Registry Path", "#fff3e0")

    doc.build(story)
    return report_filename
