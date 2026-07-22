"""Generate downloadable PDF security reports for analyzed NIDS flows."""

from collections import Counter
from datetime import datetime
from hashlib import sha256
from io import BytesIO
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend

NAVY = colors.HexColor("#0F172A")
BLUE = colors.HexColor("#2563EB")
SLATE = colors.HexColor("#475569")
LIGHT = colors.HexColor("#F1F5F9")

# Categorical palette for chart slices, reused across every visualization so a
# given category keeps a consistent look throughout the report.
PALETTE = [colors.HexColor(c) for c in (
    "#2563EB", "#EF4444", "#10B981", "#F59E0B", "#8B5CF6",
    "#EC4899", "#06B6D4", "#84CC16", "#F97316", "#64748B",
)]


def _plain(value):
    text = str(value if value is not None else "-").replace("—", "-").replace("–", "-")
    return re.sub(r"[^\x20-\x7E]", "", text).strip() or "-"


def _human_bytes(value):
    value = int(value or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024


def _style_table(table):
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _breakdown(title, values, styles):
    total = sum(values.values()) or 1
    rows = [["Category", "Count", "Share"]]
    rows.extend([[_plain(name), str(count), f"{count / total * 100:.1f}%"]
                 for name, count in values.most_common(10)])
    if len(rows) == 1:
        rows.append(["No data", "0", "0.0%"])
    return [Paragraph(title, styles["Section"]),
            _style_table(Table(rows, colWidths=[90*mm, 28*mm, 28*mm], repeatRows=1))]


def _pie_cell(title, counter, styles, max_slices=8, width=360, height=150):
    """Return [title, Drawing] for one pie chart with a side legend.

    Slices beyond ``max_slices`` are aggregated into an "Other" wedge so a long
    tail of rare categories does not turn the pie into confetti. Returns None
    when there is nothing to plot.
    """
    total = sum(counter.values())
    if total <= 0:
        return None

    items = counter.most_common(max_slices)
    if len(counter) > max_slices:
        other = total - sum(count for _, count in items)
        if other > 0:
            items.append(("Other", other))

    drawing = Drawing(width, height)
    pie = Pie()
    pie.x, pie.y = 8, 12
    pie.width = pie.height = height - 24
    pie.data = [count for _, count in items]
    pie.labels = None
    pie.sideLabels = False
    pie.simpleLabels = True
    pie.slices.strokeColor = colors.white
    pie.slices.strokeWidth = 0.75
    for i in range(len(items)):
        pie.slices[i].fillColor = PALETTE[i % len(PALETTE)]
    drawing.add(pie)

    legend = Legend()
    legend.x = pie.width + 26
    legend.y = height - 14
    legend.alignment = "right"
    legend.fontName = "Helvetica"
    legend.fontSize = 8
    legend.dxTextSpace = 5
    legend.deltay = 12
    legend.columnMaximum = 9
    legend.colorNamePairs = [
        (PALETTE[i % len(PALETTE)],
         f"{_plain(name)}  {count} ({count / total * 100:.0f}%)")
        for i, (name, count) in enumerate(items)
    ]
    drawing.add(legend)
    return [Paragraph(title, styles["Section"]), drawing]


def _chart_grid(cells):
    """Lay a list of [title, Drawing] cells into a borderless two-column grid."""
    cells = [c for c in cells if c]
    if not cells:
        return []
    rows = []
    for i in range(0, len(cells), 2):
        pair = cells[i:i + 2]
        if len(pair) == 1:
            pair.append("")
        rows.append(pair)
    table = Table(rows, colWidths=[132 * mm, 132 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return [table]


def _footer(canvas, doc):
    canvas.saveState()
    width, _ = landscape(A4)
    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.line(doc.leftMargin, 13*mm, width-doc.rightMargin, 13*mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(SLATE)
    canvas.drawString(doc.leftMargin, 8*mm, "AI Integrated Smart Packet Analyzer")
    canvas.drawRightString(width-doc.rightMargin, 8*mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_security_report(flows, alerts, analysis_mode="Network analysis",
                             confidence_threshold=0.75, anonymize_ips=False):
    """Build and return a complete security report as PDF bytes."""
    flows = [dict(row) for row in (flows or [])]
    alerts = [dict(row) for row in (alerts or [])]
    if not flows:
        raise ValueError("At least one analyzed flow is required.")

    if anonymize_ips:
        aliases = {}
        for row in flows + alerts:
            for key in ("src_ip", "dst_ip"):
                if key in row:
                    raw = str(row[key])
                    aliases.setdefault(raw, f"host-{sha256(raw.encode()).hexdigest()[:8]}")
                    row[key] = aliases[raw]

    output = BytesIO()
    doc = SimpleDocTemplate(output, pagesize=landscape(A4), leftMargin=16*mm,
                            rightMargin=16*mm, topMargin=16*mm, bottomMargin=19*mm,
                            title="Network Intrusion Detection Security Report",
                            author="AI Integrated Smart Packet Analyzer")
    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle("ReportTitle", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=23, leading=28, textColor=NAVY, alignment=TA_CENTER),
        "Subtitle": ParagraphStyle("Subtitle", parent=base["Normal"], fontSize=10,
                                   leading=14, textColor=SLATE, alignment=TA_CENTER),
        "Section": ParagraphStyle("Section", parent=base["Heading2"], fontName="Helvetica-Bold",
                                  fontSize=14, leading=18, textColor=NAVY, spaceBefore=5*mm,
                                  spaceAfter=2*mm),
        "Body": ParagraphStyle("Body", parent=base["BodyText"], fontSize=9, leading=13),
        "Metric": ParagraphStyle("Metric", parent=base["Normal"], fontName="Helvetica-Bold",
                                 fontSize=18, textColor=BLUE, alignment=TA_CENTER),
        "Label": ParagraphStyle("Label", parent=base["Normal"], fontSize=8,
                                textColor=SLATE, alignment=TA_CENTER),
    }
    total, attack_count = len(flows), len(alerts)
    ratio = attack_count / total * 100
    total_bytes = sum(int(row.get("bytes", 0) or 0) for row in flows)
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    story = [Spacer(1, 6*mm), Paragraph("Network Intrusion Detection Security Report", styles["Title"]),
             Spacer(1, 2*mm), Paragraph(
                 f"Generated {generated} | Mode: {_plain(analysis_mode)} | Alert threshold: {confidence_threshold:.0%}",
                 styles["Subtitle"]), Spacer(1, 7*mm)]
    metrics = [str(total), str(attack_count), str(total-attack_count), f"{ratio:.2f}%", _human_bytes(total_bytes)]
    labels = ["ANALYZED FLOWS", "MODEL ALERTS", "NON-ALERT FLOWS", "ALERT RATIO", "TOTAL TRAFFIC"]
    metric_table = Table([[Paragraph(v, styles["Metric"]) for v in metrics],
                          [Paragraph(v, styles["Label"]) for v in labels]],
                         colWidths=[48*mm]*5, rowHeights=[13*mm, 8*mm])
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), .8, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), .5, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    high = any("HIGH" in _plain(row.get("severity")) for row in alerts)
    priority = "HIGH" if ratio >= 20 or high else "ELEVATED" if alerts else "LOW"
    has_ground_truth = all("ground_truth" in row for row in flows)
    true_positives = sum(row.get("evaluation") == "TRUE POSITIVE" for row in flows)
    false_positives = sum(row.get("evaluation") == "FALSE POSITIVE" for row in flows)
    false_negatives = sum(row.get("evaluation") == "FALSE NEGATIVE" for row in flows)
    suppressed = sum(row.get("raw_label") == 1 and not row.get("actionable_alert", False)
                     for row in flows)
    truth_note = (
        f" Because this is benchmark simulation data, ground truth is available: "
        f"<b>{true_positives}</b> true detections, <b>{false_positives}</b> false alerts, and "
        f"<b>{false_negatives}</b> missed attacks."
        if has_ground_truth else
        f" Ground truth is not available for captured traffic, so these are unverified model alerts, not confirmed compromises. "
        f"Modern-traffic guardrails suppressed <b>{suppressed}</b> raw model positives that lacked supporting behavioral indicators."
    )
    story.extend([metric_table, Paragraph("Executive summary", styles["Section"]), Paragraph(
        f"The system analyzed <b>{total}</b> flows and raised <b>{attack_count}</b> alerts. "
        f"The intrusion ratio is <b>{ratio:.2f}%</b>, producing an overall review priority of "
        f"<b>{priority}</b>. Alerts should be correlated with firewall, endpoint, authentication, "
        f"and application logs before taking response actions.{truth_note}", styles["Body"])])

    # Visual overview — pie charts summarizing the whole capture at a glance.
    story.append(Paragraph("Visual overview", styles["Section"]))
    composition = Counter({"Alerts": attack_count, "Non-alert flows": total - attack_count})
    chart_cells = [
        _pie_cell("Traffic composition", composition, styles),
        _pie_cell("Protocol distribution",
                  Counter(_plain(x.get("protocol", "Unknown")) for x in flows), styles),
        _pie_cell("Attack categories",
                  Counter(_plain(x.get("attack_type", "Unknown")) for x in alerts), styles),
        _pie_cell("Alert severity",
                  Counter(_plain(x.get("severity", "Unknown")) for x in alerts), styles),
    ]
    grid = _chart_grid(chart_cells)
    if grid:
        story.extend(grid)
    else:
        story.append(Paragraph("No data available to visualize.", styles["Body"]))
    story.append(PageBreak())

    for section in _breakdown("Protocol distribution", Counter(_plain(x.get("protocol", "Unknown")) for x in flows), styles):
        story.append(section)
    for section in _breakdown("Detected attack categories", Counter(_plain(x.get("attack_type", "Unknown")) for x in alerts), styles):
        story.append(section)
    for section in _breakdown("Alert severity", Counter(_plain(x.get("severity", "Unknown")) for x in alerts), styles):
        story.append(section)
    if not has_ground_truth:
        for section in _breakdown("Capture policy outcomes", Counter(
                _plain(x.get("policy_reason", "No policy reason")) for x in flows), styles):
            story.append(section)
    story.append(PageBreak())
    for section in _breakdown("Top alert source hosts", Counter(_plain(x.get("src_ip", "Unknown")) for x in alerts), styles):
        story.append(section)
    for section in _breakdown("Top targeted hosts", Counter(_plain(x.get("dst_ip", "Unknown")) for x in alerts), styles):
        story.append(section)

    story.append(Paragraph("Detailed security alerts", styles["Section"]))
    rows = [["Time", "Source", "Destination", "Proto", "Attack type", "Severity", "Confidence", "Finding"]]
    # Bound the appendix so large captures cannot create an impractically large PDF.
    detailed_alerts = alerts[:500]
    for row in detailed_alerts:
        rows.append([_plain(row.get("timestamp", "-")),
                     f"{_plain(row.get('src_ip'))}:{_plain(row.get('src_port'))}",
                     f"{_plain(row.get('dst_ip'))}:{_plain(row.get('dst_port'))}",
                     _plain(row.get("protocol")), _plain(row.get("attack_type")),
                     _plain(row.get("severity")), _plain(row.get("confidence")),
                     _plain(row.get("evaluation", "UNVERIFIED MODEL ALERT"))])
    if len(rows) == 1:
        rows.append(["-", "-", "-", "-", "-", "No alerts detected", "-", "-"])
    story.append(_style_table(Table(rows, colWidths=[20*mm, 42*mm, 42*mm, 18*mm, 25*mm,
                                                     33*mm, 25*mm, 25*mm], repeatRows=1)))
    if len(alerts) > len(detailed_alerts):
        story.append(Paragraph(
            f"Showing the first {len(detailed_alerts)} of {len(alerts)} alerts. "
            "Use the CSV alert export for the complete machine-readable list.", styles["Body"]))
    story.append(Paragraph("Recommended next actions", styles["Section"]))
    recommendations = [
        "Validate high-severity and high-confidence alerts against supporting security logs.",
        "Review repeated source and destination hosts for scanning, lateral movement, or service abuse.",
        "Block or isolate systems only after corroborating the model alert with additional evidence.",
        "Retain the original PCAP and this report as investigation evidence with controlled access.",
        "Tune the threshold using known benign traffic, especially for QUIC and HTTP/3 workloads.",
    ]
    story.extend(Paragraph(f"- {item}", styles["Body"]) for item in recommendations)
    story.extend([Paragraph("Method and limitations", styles["Section"]), Paragraph(
        "Flows are classified by XGBoost models trained on UNSW-NB15 features. The binary model "
        "detects malicious flows and a second model estimates attack category. This automated report "
        "is decision support, not proof of compromise. Dataset age, encryption, incomplete captures, "
        "unseen protocols, and production network differences can cause false positives or missed attacks. "
        f"IP anonymization was <b>{'enabled' if anonymize_ips else 'disabled'}</b>.", styles["Body"])])
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return output.getvalue()
