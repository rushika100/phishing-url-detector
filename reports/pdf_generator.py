"""
PDF Report Generator for Phishing URL Detector
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

# ── Colors ───────────────────────────────────
DARK       = colors.HexColor("#0a0e1a")
CARD       = colors.HexColor("#111827")
CYAN       = colors.HexColor("#00d4ff")
GREEN      = colors.HexColor("#00cc66")
RED        = colors.HexColor("#ff4444")
AMBER      = colors.HexColor("#ffbb00")
TEXT       = colors.HexColor("#c8d8f0")
SUBTEXT    = colors.HexColor("#4a7a9b")
BORDER     = colors.HexColor("#1e3a5f")
WHITE      = colors.white

def generate_pdf(scan_data: dict, output_path: str = None) -> str:
    """
    Generate a professional PDF report from scan results.
    scan_data: dict with url, prediction, confidence, flags, vt, features
    """
    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("reports", exist_ok=True)
        output_path = f"reports/phishing_report_{ts}.pdf"

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Custom styles ─────────────────────────
    title_style = ParagraphStyle(
        "Title", parent=styles["Normal"],
        fontSize=22, fontName="Helvetica-Bold",
        textColor=CYAN, alignment=TA_CENTER, spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        fontSize=9, textColor=SUBTEXT,
        alignment=TA_CENTER, spaceAfter=20
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Normal"],
        fontSize=8, fontName="Helvetica-Bold",
        textColor=SUBTEXT, spaceBefore=16, spaceAfter=6,
        letterSpacing=1
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9, textColor=TEXT,
        leading=14, spaceAfter=6
    )
    url_style = ParagraphStyle(
        "URL", parent=styles["Normal"],
        fontSize=8, textColor=CYAN,
        leading=12, wordWrap="CJK"
    )

    # ── Header ───────────────────────────────
    story.append(Paragraph("⬡ PHISHING URL DETECTOR", title_style))
    story.append(Paragraph(
        f"Security Analysis Report  ·  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 12))

    # ── Verdict banner ───────────────────────
    pred       = scan_data.get("prediction", 0)
    conf       = scan_data.get("confidence", 0)
    url        = scan_data.get("url", "N/A")
    is_phish   = pred == 1
    verd_color = RED if is_phish else GREEN
    verd_text  = "⚠  PHISHING DETECTED" if is_phish else "✓  LEGITIMATE"
    risk_grade = "F" if is_phish and conf > 85 else "D" if is_phish else "B" if conf > 80 else "A"

    verdict_data = [[
        Paragraph(f'<font color="{verd_color.hexval()}" size="16"><b>{verd_text}</b></font>', body_style),
        Paragraph(f'<font color="{verd_color.hexval()}" size="20"><b>{risk_grade}</b></font>\n<font color="{SUBTEXT.hexval()}" size="7">RISK GRADE</font>', body_style),
    ]]
    verdict_table = Table(verdict_data, colWidths=[4.5*inch, 1*inch])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), CARD),
        ("ROUNDEDCORNERS", (0,0), (-1,-1), [8]),
        ("BOX",         (0,0), (-1,-1), 1, BORDER),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",     (0,0), (-1,-1), 14),
        ("ALIGN",       (1,0), (1,0), "CENTER"),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 12))

    # ── Target URL ───────────────────────────
    story.append(Paragraph("TARGET URL", section_style))
    url_data = [[Paragraph(url, url_style)]]
    url_table = Table(url_data, colWidths=[6.5*inch])
    url_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), CARD),
        ("BOX",        (0,0), (-1,-1), 1, BORDER),
        ("PADDING",    (0,0), (-1,-1), 10),
    ]))
    story.append(url_table)
    story.append(Spacer(1, 8))

    # ── Summary stats ────────────────────────
    story.append(Paragraph("SCAN SUMMARY", section_style))
    vt        = scan_data.get("vt", {})
    vt_result = vt.get("verdict", "N/A") if not vt.get("error") else "ERROR"
    vt_color  = RED if vt_result == "MALICIOUS" else AMBER if vt_result == "SUSPICIOUS" else GREEN

    summary_data = [
        ["ML Confidence", "VT Verdict", "VT Engines Flagged", "Risk Grade"],
        [
            Paragraph(f'<font color="{verd_color.hexval()}"><b>{conf}%</b></font>', body_style),
            Paragraph(f'<font color="{vt_color.hexval()}"><b>{vt_result}</b></font>', body_style),
            Paragraph(f'<b>{vt.get("malicious", 0)}/{vt.get("total", 0)}</b>', body_style),
            Paragraph(f'<font color="{verd_color.hexval()}"><b>{risk_grade}</b></font>', body_style),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[1.6*inch]*4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0),  BORDER),
        ("BACKGROUND",  (0,1), (-1,-1), CARD),
        ("TEXTCOLOR",   (0,0), (-1,0),  SUBTEXT),
        ("FONTSIZE",    (0,0), (-1,0),  7),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",     (0,0), (-1,-1), 10),
        ("BOX",         (0,0), (-1,-1), 1, BORDER),
        ("INNERGRID",   (0,0), (-1,-1), 0.5, BORDER),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8))

    # ── Warning signals ──────────────────────
    flags = scan_data.get("flags", [])
    story.append(Paragraph("WARNING SIGNALS", section_style))

    if not flags:
        story.append(Paragraph(
            '<font color="#00cc66">✓ No suspicious signals detected</font>',
            body_style
        ))
    else:
        flag_rows = [["Severity", "Description"]]
        for sev, msg in flags:
            sev_color = RED if sev == "HIGH" else AMBER
            flag_rows.append([
                Paragraph(f'<font color="{sev_color.hexval()}"><b>{sev}</b></font>', body_style),
                Paragraph(msg, body_style)
            ])
        flag_table = Table(flag_rows, colWidths=[1*inch, 5.5*inch])
        flag_table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  BORDER),
            ("BACKGROUND",  (0,1), (-1,-1), CARD),
            ("TEXTCOLOR",   (0,0), (-1,0),  SUBTEXT),
            ("FONTSIZE",    (0,0), (-1,0),  7),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("PADDING",     (0,0), (-1,-1), 8),
            ("BOX",         (0,0), (-1,-1), 1, BORDER),
            ("INNERGRID",   (0,0), (-1,-1), 0.5, BORDER),
        ]))
        story.append(flag_table)
    story.append(Spacer(1, 8))

    # ── VirusTotal breakdown ─────────────────
    if not vt.get("error"):
        story.append(Paragraph("VIRUSTOTAL BREAKDOWN", section_style))
        vt_rows = [
            ["Malicious", "Suspicious", "Harmless", "Undetected", "Total Engines"],
            [
                Paragraph(f'<font color="#ff4444"><b>{vt.get("malicious",0)}</b></font>', body_style),
                Paragraph(f'<font color="#ffbb00"><b>{vt.get("suspicious",0)}</b></font>', body_style),
                Paragraph(f'<font color="#00cc66"><b>{vt.get("harmless",0)}</b></font>', body_style),
                Paragraph(f'<b>{vt.get("undetected",0)}</b>', body_style),
                Paragraph(f'<b>{vt.get("total",0)}</b>', body_style),
            ]
        ]
        vt_table = Table(vt_rows, colWidths=[1.3*inch]*5)
        vt_table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  BORDER),
            ("BACKGROUND",  (0,1), (-1,-1), CARD),
            ("TEXTCOLOR",   (0,0), (-1,0),  SUBTEXT),
            ("FONTSIZE",    (0,0), (-1,0),  7),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("ALIGN",       (0,0), (-1,-1), "CENTER"),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("PADDING",     (0,0), (-1,-1), 10),
            ("BOX",         (0,0), (-1,-1), 1, BORDER),
            ("INNERGRID",   (0,0), (-1,-1), 0.5, BORDER),
        ]))
        story.append(vt_table)
        story.append(Spacer(1, 8))

    # ── Remediation ──────────────────────────
    story.append(Paragraph("REMEDIATION ADVICE", section_style))
    remediations = []
    feats = scan_data.get("features", {})

    if feats.get("HTTPS") == 0:
        remediations.append("Always verify the site uses HTTPS before entering credentials.")
    if feats.get("UsingIP") == 1:
        remediations.append("Never trust sites using raw IP addresses instead of domain names.")
    if feats.get("SubDomains", 0) >= 3:
        remediations.append("Multiple subdomains are a common trick — verify the root domain carefully.")
    if any(f[0] == "HIGH" for f in flags):
        remediations.append("Multiple HIGH severity signals detected — do not visit or enter any data.")
    if vt.get("malicious", 0) > 0:
        remediations.append("VirusTotal flagged this URL — report it to your IT/security team immediately.")
    if not remediations:
        remediations.append("No immediate action required. Continue following safe browsing practices.")

    for i, r in enumerate(remediations):
        story.append(Paragraph(f"  {i+1}. {r}", body_style))

    # ── Footer ───────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated by Phishing URL Detector · ML + VirusTotal · For authorized security research only",
        ParagraphStyle("Footer", parent=styles["Normal"],
                       fontSize=7, textColor=SUBTEXT, alignment=TA_CENTER)
    ))

    doc.build(story)
    return output_path