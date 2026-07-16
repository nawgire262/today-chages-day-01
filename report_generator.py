<<<<<<< HEAD
"""Exports the current SentinelShield findings as PDF or Excel reports."""

from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart


class ReportGenerator:
    """Create reports from alert history and the latest completed scan."""

    def __init__(self, alert_file="alert_history.csv", scan_file="current_scan.csv"):
        self.alert_file = alert_file
        self.scan_file = scan_file

    @staticmethod
    def _load_csv(path):
        try:
            return pd.read_csv(path, on_bad_lines="skip") if Path(path).exists() else pd.DataFrame()
        except (OSError, pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError):
            return pd.DataFrame()

    def load_alerts(self):
        return self._load_csv(self.alert_file)

    def load_scan_data(self):
        return self._load_csv(self.scan_file)

    @staticmethod
    def _table(frame, columns, max_rows=20):
        """Build a readable, bounded table that fits on an A4 page."""
        available = [column for column in columns if column in frame.columns]
        if not available:
            return None
        rows = [available]
        for _, row in frame[available].head(max_rows).fillna("").iterrows():
            rows.append([str(value)[:36] for value in row.tolist()])
        table = Table(
            rows,
            colWidths=[(7.5 * inch) / len(available)] * len(available),
            repeatRows=1,
            hAlign="LEFT",
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e78")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b7c9d6")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#edf4f8")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    def generate_excel_report(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Threat_Report_{timestamp}.xlsx"
        with pd.ExcelWriter(filename, engine="openpyxl") as writer:
            self.load_scan_data().to_excel(writer, sheet_name="Current Scan", index=False)
            self.load_alerts().to_excel(writer, sheet_name="Alert History", index=False)
        return filename

    def generate_pdf_report(self, scan_data=None):
        """Generate a report with live scan data plus persisted alert history."""
        alerts = self.load_alerts()
        scan = pd.DataFrame(scan_data).copy() if scan_data is not None else self.load_scan_data()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Threat_Report_{timestamp}.pdf"
        styles = getSampleStyleSheet()
        elements = [
            Paragraph("SentinelShield Threat Detection Report", styles["Title"]),
            Paragraph(f"Generated: {escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", styles["Normal"]),
            Spacer(1, 14),
        ]

        high_risk = scan[scan["Threat_Level"].isin(["HIGH", "CRITICAL"])] if "Threat_Level" in scan else pd.DataFrame()
        highest_risk = float(pd.to_numeric(scan["Combined_Risk"], errors="coerce").max()) if "Combined_Risk" in scan and not scan.empty else 0.0
        elements.extend([
            Paragraph("Live Scan Summary", styles["Heading2"]),
            Paragraph(
                f"<b>Networks scanned:</b> {len(scan)} &nbsp;&nbsp; <b>High/Critical threats:</b> {len(high_risk)} &nbsp;&nbsp; <b>Highest risk:</b> {highest_risk:.1f}%",
                styles["Normal"],
            ),
            Spacer(1, 8),
        ])
        if "Threat_Level" in scan:
            counts = scan["Threat_Level"].value_counts()
            if not counts.empty:
                chart = VerticalBarChart()
                chart.x = 35
                chart.y = 25
                chart.height = 130
                chart.width = 440
                chart.data = [counts.tolist()]
                chart.categoryAxis.categoryNames = counts.index.tolist()
                chart.valueAxis.valueMin = 0
                chart.valueAxis.valueMax = max(1, int(counts.max()) + 1)
                chart.barWidth = 24
                chart.bars[0].fillColor = colors.HexColor("#d9534f")
                drawing = Drawing(500, 180)
                drawing.add(chart)
                elements.extend([Spacer(1, 8), Paragraph("Threat-level distribution", styles["Heading3"]), drawing])
        scan_table = self._table(scan, ["SSID", "BSSID", "RSSI", "Security", "ML_Risk", "Combined_Risk", "Threat_Level"])
        elements.append(scan_table if scan_table is not None else Paragraph("No completed scan data is available yet.", styles["Normal"]))

        cloud_table = self._table(scan, ["SSID", "VirusTotal_Risk", "AbuseIPDB_Risk", "BSSID_Reputation", "OpenPhish_Risk", "Cloud_Risk"], max_rows=15)
        if cloud_table is not None:
            elements.extend([Spacer(1, 14), Paragraph("Cloud Threat Intelligence Summary", styles["Heading2"]), cloud_table])

        elements.extend([Spacer(1, 16), Paragraph("Alert History", styles["Heading2"]), Paragraph(f"<b>Total recorded alerts:</b> {len(alerts)}", styles["Normal"]), Spacer(1, 8)])
        alert_table = self._table(alerts, ["Time", "SSID", "BSSID", "Risk", "Reason"])
        elements.append(alert_table if alert_table is not None else Paragraph("No alerts have been recorded.", styles["Normal"]))
        SimpleDocTemplate(filename, pagesize=A4, rightMargin=0.35 * inch, leftMargin=0.35 * inch).build(elements)
        return filename
=======
# report_generator.py

import pandas as pd
from datetime import datetime
from pathlib import Path

# PDF
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet


class ReportGenerator:

    def __init__(self):
        self.alert_file = "alert_history.csv"
        self.scan_file = "current_scan.csv"

    # ---------------------------------------------------
    # Load Data
    # ---------------------------------------------------
    def load_alerts(self):

        if Path(self.alert_file).exists():
            return pd.read_csv(self.alert_file)

        return pd.DataFrame()

    # ---------------------------------------------------
    # Excel Export
    # ---------------------------------------------------
    def generate_excel_report(self):

        alerts = self.load_alerts()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"Threat_Report_{timestamp}.xlsx"

        with pd.ExcelWriter(filename, engine="openpyxl") as writer:

            alerts.to_excel(
                writer,
                sheet_name="Threat History",
                index=False
            )

        return filename

    # ---------------------------------------------------
    # PDF Export
    # ---------------------------------------------------
    def generate_pdf_report(self):

        alerts = self.load_alerts()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"Threat_Report_{timestamp}.pdf"

        doc = SimpleDocTemplate(filename)

        styles = getSampleStyleSheet()

        elements = []

        title = Paragraph(
            "SentinelShield Threat Detection Report",
            styles["Title"]
        )

        elements.append(title)
        elements.append(Spacer(1, 12))

        elements.append(
            Paragraph(
                f"Generated: {datetime.now()}",
                styles["Normal"]
            )
        )

        elements.append(Spacer(1, 20))

        total_alerts = len(alerts)

        elements.append(
            Paragraph(
                f"<b>Total Alerts:</b> {total_alerts}",
                styles["Heading2"]
            )
        )

        elements.append(Spacer(1, 12))

        if not alerts.empty:

            table_data = [alerts.columns.tolist()]

            for _, row in alerts.head(20).iterrows():
                table_data.append(row.astype(str).tolist())

            table = Table(table_data)

            table.setStyle(
                TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.grey),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),

                    ('GRID', (0,0), (-1,-1), 1, colors.black),

                    ('BACKGROUND', (0,1), (-1,-1), colors.beige)
                ])
            )

            elements.append(table)

        doc.build(elements)

        return filename
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
