"""
Professional PDF Report Generator
Clean dark-themed security report with canvas-based layout
"""

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

W, H = A4  # 595 x 842 pts

# ── Color Palette ─────────────────────────────
BG       = colors.HexColor("#0a0e1a")
CARD     = colors.HexColor("#111827")
CARD2    = colors.HexColor("#1a2235")
BORDER   = colors.HexColor("#1e3a5f")
CYAN     = colors.HexColor("#00d4ff")
GREEN    = colors.HexColor("#00cc66")
RED      = colors.HexColor("#ff4444")
AMBER    = colors.HexColor("#ffbb00")
ORANGE   = colors.HexColor("#ff8800")
TEXT     = colors.HexColor("#c8d8f0")
SUBTEXT  = colors.HexColor("#4a7a9b")
WHITE    = colors.white
BLACK    = colors.black

def draw_rounded_rect(c, x, y, w, h, radius=4, fill_color=None, stroke_color=None, stroke_width=0.5):
    c.saveState()
    if fill_color:
        c.setFillColor(fill_color)
    if stroke_color:
        c.setStrokeColor(stroke_color)
        c.setLineWidth(stroke_width)
    p = c.beginPath()
    p.moveTo(x + radius, y)
    p.lineTo(x + w - radius, y)
    p.arcTo(x + w - 2*radius, y, x + w, y + 2*radius, -90, 90)
    p.lineTo(x + w, y + h - radius)
    p.arcTo(x + w - 2*radius, y + h - 2*radius, x + w, y + h, 0, 90)
    p.lineTo(x + radius, y + h)
    p.arcTo(x, y + h - 2*radius, x + 2*radius, y + h, 90, 90)
    p.lineTo(x, y + radius)
    p.arcTo(x, y, x + 2*radius, y + 2*radius, 180, 90)
    p.close()
    if fill_color and stroke_color:
        c.drawPath(p, fill=1, stroke=1)
    elif fill_color:
        c.drawPath(p, fill=1, stroke=0)
    elif stroke_color:
        c.drawPath(p, fill=0, stroke=1)
    c.restoreState()

def draw_page_background(c, width, height):
    """Draw full page dark background"""
    c.setFillColor(BG)
    c.rect(0, 0, width, height, fill=1, stroke=0)

def draw_header(c, width, height):
    """Draw professional header with gradient-like effect"""
    # Header background
    draw_rounded_rect(c, 20*mm, height - 45*mm, width - 40*mm, 38*mm,
                     radius=6, fill_color=CARD, stroke_color=BORDER, stroke_width=0.5)

    # Cyan accent bar on left
    c.setFillColor(CYAN)
    c.rect(20*mm, height - 45*mm, 2*mm, 38*mm, fill=1, stroke=0)

    # Logo / Icon area
    c.setFillColor(CYAN)
    c.setFont("Helvetica-Bold", 24)
    c.drawString(30*mm, height - 20*mm, "⬡")

    # Title
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(42*mm, height - 19*mm, "PHISHING URL DETECTOR")

    # Subtitle
    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica", 8)
    c.drawString(42*mm, height - 26*mm, "Security Analysis Report")

    # Date on right
    date_str = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica", 8)
    c.drawRightString(width - 25*mm, height - 19*mm, date_str)

    # Badges
    badges = [("ML + VirusTotal", CYAN), ("OWASP Aligned", GREEN), ("Automated Scan", AMBER)]
    bx = width - 25*mm
    for label, color in reversed(badges):
        tw = c.stringWidth(label, "Helvetica-Bold", 7) + 8*mm
        bx -= tw + 3*mm
        draw_rounded_rect(c, bx, height - 32*mm, tw, 5*mm,
                         radius=2, fill_color=color)
        c.setFillColor(BLACK)
        c.setFont("Helvetica-Bold", 7)
        c.drawString(bx + 3*mm, height - 29.5*mm, label)

def draw_verdict_section(c, width, height, scan_data):
    """Draw the main verdict banner"""
    pred     = scan_data.get("prediction", 0)
    conf     = scan_data.get("confidence", 0)
    url      = scan_data.get("url", "N/A")
    is_phish = pred == 1

    verdict_color = RED if is_phish else GREEN
    verdict_text  = "PHISHING DETECTED" if is_phish else "LEGITIMATE"
    risk_grade    = "F" if (is_phish and conf > 85) else "D" if is_phish else "A" if conf > 85 else "B"
    grade_color   = RED if risk_grade in ("F","D") else GREEN

    y = height - 58*mm

    # Verdict card background
    draw_rounded_rect(c, 20*mm, y - 28*mm, width - 40*mm, 30*mm,
                     radius=6, fill_color=CARD, stroke_color=verdict_color, stroke_width=1)

    # Left colored accent
    c.setFillColor(verdict_color)
    c.rect(20*mm, y - 28*mm, 1.5*mm, 30*mm, fill=1, stroke=0)

    # Verdict icon + text
    icon = "✗" if is_phish else "✓"
    c.setFillColor(verdict_color)
    c.setFont("Helvetica-Bold", 28)
    c.drawString(28*mm, y - 12*mm, icon)

    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(42*mm, y - 8*mm, verdict_text)

    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica", 8)
    c.drawString(42*mm, y - 15*mm, f"ML Confidence: {conf}%")

    # Confidence bar background
    bar_x = 42*mm
    bar_y = y - 22*mm
    bar_w = 80*mm
    bar_h = 4*mm
    draw_rounded_rect(c, bar_x, bar_y, bar_w, bar_h,
                     radius=2, fill_color=CARD2)
    fill_w = bar_w * (conf / 100)
    draw_rounded_rect(c, bar_x, bar_y, fill_w, bar_h,
                     radius=2, fill_color=verdict_color)

    # Risk grade circle
    cx = width - 38*mm
    cy = y - 13*mm
    c.setFillColor(CARD2)
    c.circle(cx, cy, 12*mm, fill=1, stroke=0)
    c.setStrokeColor(grade_color)
    c.setLineWidth(2)
    c.circle(cx, cy, 12*mm, fill=0, stroke=1)
    c.setFillColor(grade_color)
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(cx, cy - 3*mm, risk_grade)
    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica", 6)
    c.drawCentredString(cx, cy - 8*mm, "RISK GRADE")

    # URL box
    url_y = y - 35*mm
    draw_rounded_rect(c, 20*mm, url_y - 8*mm, width - 40*mm, 10*mm,
                     radius=4, fill_color=CARD2, stroke_color=BORDER, stroke_width=0.5)
    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica-Bold", 7)
    c.drawString(24*mm, url_y - 1*mm, "TARGET URL")
    short_url = url if len(url) < 85 else url[:82] + "..."
    c.setFillColor(CYAN)
    c.setFont("Helvetica", 8)
    c.drawString(24*mm, url_y - 5.5*mm, short_url)

    return y - 48*mm

def draw_stats_row(c, width, y, scan_data):
    """Draw 4 stat cards in a row"""
    vt      = scan_data.get("vt", {})
    flags   = scan_data.get("flags", [])
    conf    = scan_data.get("confidence", 0)
    pred    = scan_data.get("prediction", 0)

    vt_verdict = vt.get("verdict", "N/A") if not vt.get("error") else "ERROR"
    vt_color   = RED if vt_verdict == "MALICIOUS" else AMBER if vt_verdict == "SUSPICIOUS" else GREEN
    high_count = len([f for f in flags if f[0] == "HIGH"])

    stats = [
        (f"{conf}%",          "ML CONFIDENCE",    RED if pred == 1 else GREEN),
        (vt_verdict,          "VIRUSTOTAL",        vt_color),
        (f"{vt.get('malicious',0)}/{vt.get('total',0)}", "ENGINES FLAGGED", RED if vt.get('malicious',0) > 0 else GREEN),
        (str(high_count),     "HIGH SIGNALS",      RED if high_count > 0 else GREEN),
    ]

    card_w = (width - 44*mm) / 4
    for i, (value, label, color) in enumerate(stats):
        x = 20*mm + i * (card_w + 1.3*mm)
        draw_rounded_rect(c, x, y - 18*mm, card_w, 20*mm,
                         radius=5, fill_color=CARD, stroke_color=BORDER, stroke_width=0.5)
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", 13)
        c.drawCentredString(x + card_w/2, y - 9*mm, value)
        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica", 6)
        c.drawCentredString(x + card_w/2, y - 15*mm, label)

    return y - 25*mm

def draw_section_title(c, x, y, title):
    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica-Bold", 7)
    c.drawString(x, y, title)
    c.setStrokeColor(BORDER)
    c.setLineWidth(0.3)
    c.line(x, y - 1.5*mm, x + 170*mm, y - 1.5*mm)

def draw_flags_section(c, width, y, flags):
    """Draw warning signals"""
    draw_section_title(c, 20*mm, y, "WARNING SIGNALS")
    y -= 5*mm

    if not flags:
        draw_rounded_rect(c, 20*mm, y - 8*mm, width - 40*mm, 10*mm,
                         radius=4, fill_color=CARD, stroke_color=GREEN, stroke_width=0.5)
        c.setFillColor(GREEN)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(24*mm, y - 3.5*mm, "✓  No suspicious signals detected — URL appears clean")
        return y - 15*mm

    for sev, msg in flags:
        color  = RED if sev == "HIGH" else AMBER
        label  = "HIGH" if sev == "HIGH" else "WARN"
        row_h  = 10*mm

        draw_rounded_rect(c, 20*mm, y - row_h, width - 40*mm, row_h,
                         radius=3, fill_color=CARD, stroke_color=color, stroke_width=0.3)

        # Severity badge
        badge_w = 14*mm
        draw_rounded_rect(c, 22*mm, y - row_h + 1.5*mm, badge_w, 7*mm,
                         radius=2, fill_color=color)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 6)
        c.drawCentredString(22*mm + badge_w/2, y - row_h + 4*mm, label)

        # Message
        short_msg = msg if len(msg) < 90 else msg[:87] + "..."
        c.setFillColor(TEXT)
        c.setFont("Helvetica", 8)
        c.drawString(39*mm, y - row_h + 4*mm, short_msg)

        y -= row_h + 1*mm

    return y - 3*mm

def draw_vt_section(c, width, y, vt):
    """Draw VirusTotal breakdown"""
    draw_section_title(c, 20*mm, y, "VIRUSTOTAL THREAT INTELLIGENCE")
    y -= 5*mm

    if vt.get("error"):
        draw_rounded_rect(c, 20*mm, y - 8*mm, width - 40*mm, 10*mm,
                         radius=4, fill_color=CARD, stroke_color=BORDER, stroke_width=0.5)
        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica", 8)
        c.drawString(24*mm, y - 3.5*mm, f"Could not reach VirusTotal: {vt.get('error','')[:60]}")
        return y - 15*mm

    # Main VT card
    is_mal = vt.get("malicious", 0) > 0
    border_color = RED if is_mal else GREEN

    draw_rounded_rect(c, 20*mm, y - 22*mm, width - 40*mm, 24*mm,
                     radius=5, fill_color=CARD, stroke_color=border_color, stroke_width=0.8)

    # Verdict
    verdict = vt.get("verdict", "CLEAN")
    v_color = RED if verdict == "MALICIOUS" else AMBER if verdict == "SUSPICIOUS" else GREEN
    c.setFillColor(v_color)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(25*mm, y - 9*mm, verdict)
    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica", 8)
    c.drawString(25*mm, y - 15*mm, f"{vt.get('malicious',0)} of {vt.get('total',0)} security engines flagged this URL")

    # Mini stats
    mini_stats = [
        ("Malicious",  vt.get("malicious",0),  RED),
        ("Suspicious", vt.get("suspicious",0), AMBER),
        ("Harmless",   vt.get("harmless",0),   GREEN),
        ("Undetected", vt.get("undetected",0), SUBTEXT),
    ]
    sx = width - 100*mm
    for label, val, color in mini_stats:
        draw_rounded_rect(c, sx, y - 18*mm, 20*mm, 12*mm,
                         radius=3, fill_color=CARD2)
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(sx + 10*mm, y - 11*mm, str(val))
        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica", 6)
        c.drawCentredString(sx + 10*mm, y - 16*mm, label)
        sx += 21*mm

    return y - 29*mm

def draw_remediation(c, width, y, scan_data):
    """Draw remediation advice"""
    draw_section_title(c, 20*mm, y, "REMEDIATION ADVICE")
    y -= 5*mm

    flags    = scan_data.get("features", {})
    vt       = scan_data.get("vt", {})
    all_flags = scan_data.get("flags", [])

    remediations = []
    if flags.get("HTTPS") == 0:
        remediations.append("Always verify the site uses HTTPS before entering any credentials or personal data.")
    if flags.get("UsingIP") == 1:
        remediations.append("Never trust websites using raw IP addresses instead of proper domain names.")
    if flags.get("SubDomains", 0) >= 3:
        remediations.append("Verify the root domain carefully — multiple subdomains are a common phishing technique.")
    if any(f[0] == "HIGH" for f in all_flags):
        remediations.append("Multiple HIGH severity signals detected — do not visit this URL or enter any information.")
    if vt.get("malicious", 0) > 0:
        remediations.append("VirusTotal flagged this URL — report it to your IT/security team immediately.")
    if not remediations:
        remediations.append("No immediate action required. Continue following safe browsing practices.")
        remediations.append("Always verify URLs before clicking, especially in emails from unknown senders.")

    for i, rem in enumerate(remediations):
        row_h = 9*mm
        draw_rounded_rect(c, 20*mm, y - row_h, width - 40*mm, row_h,
                         radius=3, fill_color=CARD, stroke_color=BORDER, stroke_width=0.3)

        # Number badge
        c.setFillColor(CYAN)
        c.circle(25*mm, y - row_h/2, 3*mm, fill=1, stroke=0)
        c.setFillColor(BLACK)
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(25*mm, y - row_h/2 - 1*mm, str(i+1))

        c.setFillColor(TEXT)
        c.setFont("Helvetica", 8)
        short = rem if len(rem) < 95 else rem[:92] + "..."
        c.drawString(30*mm, y - row_h/2 - 1.5*mm, short)
        y -= row_h + 1*mm

    return y

def draw_footer(c, width):
    """Draw professional footer"""
    # Footer bar
    c.setFillColor(CARD)
    c.rect(0, 0, width, 18*mm, fill=1, stroke=0)
    c.setStrokeColor(BORDER)
    c.setLineWidth(0.5)
    c.line(0, 18*mm, width, 18*mm)

    c.setFillColor(CYAN)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(20*mm, 11*mm, "⬡ Phishing URL Detector")

    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica", 7)
    c.drawString(20*mm, 6*mm, "ML + VirusTotal · Python · scikit-learn · For authorized security research only")

    c.setFillColor(SUBTEXT)
    c.setFont("Helvetica", 7)
    c.drawRightString(width - 20*mm, 11*mm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawRightString(width - 20*mm, 6*mm, "CONFIDENTIAL — Security Report")

def generate_pdf(scan_data: dict, output_path: str = None) -> str:
    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("reports", exist_ok=True)
        output_path = f"reports/phishing_report_{ts}.pdf"

    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    # Background
    draw_page_background(c, width, height)

    # Header
    draw_header(c, width, height)

    # Verdict
    y = draw_verdict_section(c, width, height, scan_data)

    # Stats row
    y = draw_stats_row(c, width, y, scan_data)
    y -= 5*mm

    # Flags
    y = draw_flags_section(c, width, y, scan_data.get("flags", []))
    y -= 5*mm

    # VirusTotal
    y = draw_vt_section(c, width, y, scan_data.get("vt", {}))
    y -= 5*mm

    # Remediation
    y = draw_remediation(c, width, y, scan_data)

    # Footer
    draw_footer(c, width)

    c.save()
    return output_path


if __name__ == "__main__":
    # Test with sample data
    test_data = {
        "url": "http://secure-login-paypal-verify.xyz/account/confirm?ref=SEC2024",
        "prediction": 1,
        "confidence": 85.0,
        "flags": [
            ["HIGH", "Uses HTTP not HTTPS — no encryption, easy to spoof"],
            ["HIGH", "Suspicious TLD (.xyz) — free domains used by attackers"],
            ["HIGH", "4 phishing keywords found (login, verify, secure, account)"],
            ["WARN", "3 hyphens in domain — e.g. secure-login-google.com"],
        ],
        "vt": {
            "malicious": 3,
            "suspicious": 1,
            "harmless": 45,
            "undetected": 23,
            "total": 72,
            "verdict": "MALICIOUS"
        },
        "features": {
            "HTTPS": 0,
            "UsingIP": 0,
            "SubDomains": 1,
            "Symbol@": 0,
            "Redirecting//": 0,
            "LongURL": 1,
        }
    }
    path = generate_pdf(test_data, "/tmp/test_report.pdf")
    print(f"PDF saved to: {path}")