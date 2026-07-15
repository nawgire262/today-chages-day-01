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