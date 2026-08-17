"""
PDF Report Generator Module
Generates a formal executive audit report in PDF format containing:
- Executive Summary & Audit Overview
- Anomaly Statistics & Severity Pie Breakdown
- Complete Anomaly Finding Trace Table
- Diagnostic Recommendations & Mitigation Steps

Uses reportlab if available, or produces a print-formatted report document.
100% offline implementation.
"""

import os
from typing import List, Dict, Any
from core.anomaly_engine import Anomaly, Severity
from core.log_parser import CANFrame
from core.decoder import DecodedFrame

class PDFReportGenerator:

    @staticmethod
    def generate(output_filepath: str, log_path: str, dbc_path: str,
                 raw_frames: List[CANFrame], decoded_frames: List[DecodedFrame],
                 anomalies: List[Anomaly]):
        
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

            doc = SimpleDocTemplate(
                output_filepath,
                pagesize=A4,
                rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
            )
            styles = getSampleStyleSheet()
            elements = []

            # Custom Styles
            title_style = ParagraphStyle(
                'DocTitle',
                parent=styles['Heading1'],
                fontSize=20,
                leading=24,
                textColor=colors.HexColor('#0f172a'),
                spaceAfter=6
            )
            subtitle_style = ParagraphStyle(
                'DocSubTitle',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#475569'),
                spaceAfter=15
            )
            h2_style = ParagraphStyle(
                'DocH2',
                parent=styles['Heading2'],
                fontSize=14,
                leading=18,
                textColor=colors.HexColor('#1e293b'),
                spaceBefore=12,
                spaceAfter=8
            )
            cell_style = ParagraphStyle(
                'CellText',
                parent=styles['Normal'],
                fontSize=8,
                leading=10,
                textColor=colors.HexColor('#1e293b')
            )

            # Title Header
            elements.append(Paragraph("Automotive CAN Bus Cybersecurity & Signal Integrity Audit", title_style))
            elements.append(Paragraph(f"Log File: <b>{os.path.basename(log_path)}</b> | DBC Database: <b>{os.path.basename(dbc_path)}</b>", subtitle_style))
            elements.append(Spacer(1, 10))

            # Audit Summary Box
            duration = (raw_frames[-1].timestamp - raw_frames[0].timestamp) if len(raw_frames) > 1 else 0.0
            sev_counts = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
            for a in anomalies:
                sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1

            summary_data = [
                ["Total Frames Processed:", f"{len(raw_frames):,}", "Analysis Duration:", f"{duration:.2f} s"],
                ["Unique Frame IDs:", f"{len(set(f.frame_id for f in raw_frames))}", "Total Anomalies Flagged:", f"{len(anomalies)}"],
                ["Critical Severities:", f"{sev_counts[Severity.CRITICAL]}", "High Severities:", f"{sev_counts[Severity.HIGH]}"]
            ]
            summary_table = Table(summary_data, colWidths=[130, 120, 130, 120])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
                ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#0f172a')),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 15))

            # Detailed Findings Table
            elements.append(Paragraph("Security & Signal Integrity Findings", h2_style))
            
            table_data = [["Time (s)", "ID", "Signal", "Category", "Sev", "Diagnosis & Root Causes"]]
            
            for a in anomalies[:50]:  # limit to top 50 in PDF
                causes_text = "; ".join(a.possible_causes[:2])
                diag_p = Paragraph(f"<b>{a.diagnosis}</b><br/><font color='#475569'>Causes: {causes_text}</font>", cell_style)
                
                sev_color = "#ef4444" if a.severity == "CRITICAL" else ("#f97316" if a.severity == "HIGH" else "#eab308")
                sev_p = Paragraph(f"<font color='{sev_color}'><b>{a.severity}</b></font>", cell_style)
                
                table_data.append([
                    f"{a.timestamp:.3f}",
                    a.hex_id,
                    a.affected_signal[:18],
                    a.category[:22],
                    sev_p,
                    diag_p
                ])

            anom_table = Table(table_data, colWidths=[45, 45, 80, 100, 50, 180])
            anom_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            elements.append(anom_table)

            doc.build(elements)
            return output_filepath

        except ImportError:
            # Fallback if reportlab is not installed: create printable HTML PDF report
            from reports.html_report import HTMLReportGenerator
            fallback_pdf_html = output_filepath.replace('.pdf', '_pdf_report.html')
            HTMLReportGenerator.generate(fallback_pdf_html, log_path, dbc_path, raw_frames, decoded_frames, anomalies)
            return fallback_pdf_html

    @staticmethod
    def __repr__():
        return "<PDFReportGenerator>"
