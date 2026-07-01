from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.colors import HexColor
from datetime import datetime


def create_pdf(results):

    filename = "report.pdf"

    doc = SimpleDocTemplate(
        filename
    )

    styles = getSampleStyleSheet()

    title = styles["Title"]
    title.alignment = TA_CENTER
    title.textColor = HexColor("#0B5ED7")

    heading = styles["Heading2"]
    heading.textColor = HexColor("#0B5ED7")

    normal = styles["BodyText"]

    story = []

    # ==================================
    # TITLE
    # ==================================

    story.append(
        Paragraph(
            "PhishGuard AI",
            title
        )
    )

    story.append(
        Paragraph(
            "Phishing Investigation Report",
            heading
        )
    )

    story.append(
        Paragraph(
            datetime.now().strftime(
                "%d %B %Y  |  %H:%M"
            ),
            normal
        )
    )

    story.append(
        Spacer(1,20)
    )

    # ==================================
    # EXECUTIVE SUMMARY
    # ==================================

    story.append(
        Paragraph(
            "Executive Summary",
            heading
        )
    )

    story.append(
        Paragraph(
            f"<b>Threat Score:</b> {results['ThreatScore']} / 100",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Level:</b> {results['Risk']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>Email Spoofing:</b> {results['SpoofingRisk']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>VirusTotal:</b> {results['VT_Summary']}",
            normal
        )
    )

    story.append(
        Spacer(1,20)
    )

    # ==================================
    # EMAIL DETAILS
    # ==================================

    story.append(
        Paragraph(
            "Email Details",
            heading
        )
    )

    story.append(
        Paragraph(
            f"<b>From:</b> {results['From']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>Subject:</b> {results['Subject']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>Return Path:</b> {results['Return-Path']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>Sender IP:</b> {results['SenderIP']}",
            normal
        )
    )

    story.append(
        Spacer(1,20)
    )

    # ==================================
    # AUTHENTICATION
    # ==================================

    story.append(
        Paragraph(
            "Authentication",
            heading
        )
    )

    story.append(
        Paragraph(
            f"<b>SPF:</b> {results['SPF']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>DKIM:</b> {results['DKIM']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>DMARC:</b> {results['DMARC']}",
            normal
        )
    )

    story.append(
        Spacer(1,20)
    )

    # ==================================
    # DOMAIN INTELLIGENCE
    # ==================================

    story.append(
        Paragraph(
            "Domain Intelligence",
            heading
        )
    )

    domain_data = [

        ["Registrar", results["Registrar"]],

        ["Creation Date", results["CreationDate"]],

        ["Expiration Date", results["ExpirationDate"]],

        ["Country", results["Country"]],

        ["ISP", results["ISP"]]

    ]

    domain_table = Table(
        domain_data,
        colWidths=[170,300]
    )

    domain_table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(0,-1),HexColor("#E8F1FF")),

        ("GRID",(0,0),(-1,-1),0.5,colors.grey),

        ("BOTTOMPADDING",(0,0),(-1,-1),8),

        ("TOPPADDING",(0,0),(-1,-1),8),

        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold")

    ]))

    story.append(domain_table)

    story.append(Spacer(1,20))

    # ===========================
    # PAGE BREAK
    # ===========================

    story.append(PageBreak())


    # ==================================
    # URL INTELLIGENCE
    # ==================================

    story.append(
        Paragraph(
            "URL Intelligence",
            heading
        )
    )

    url_data = [

        ["URL","Risk","VirusTotal","Age"]

    ]

    for url in results["URL_Intelligence"]:

        url_data.append([

            url["domain"],

            url["risk"],

            url["vt"],

            url["age"]

        ])

    url_table = Table(
        url_data,
        colWidths=[220,70,90,80]
    )

    url_table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),HexColor("#0B5ED7")),

        ("TEXTCOLOR",(0,0),(-1,0),colors.white),

        ("GRID",(0,0),(-1,-1),0.5,colors.grey),

        ("BACKGROUND",(0,1),(-1,-1),HexColor("#F7F9FC")),

        ("BOTTOMPADDING",(0,0),(-1,-1),8),

        ("TOPPADDING",(0,0),(-1,-1),8),

        ("ALIGN",(1,1),(-1,-1),"CENTER")

    ]))

    story.append(url_table)

    story.append(Spacer(1,20))

    # ==================================
    # IOC TABLE
    # ==================================

    story.append(
        Paragraph(
            "Indicators of Compromise",
            heading
        )
    )

    ioc_data = [

        ["Type","Indicator"]

    ]

    for ioc in results["IOCs"]:

        ioc_data.append([

            ioc["type"],

            ioc["value"]

        ])

    ioc_table = Table(
        ioc_data,
        colWidths=[130,340]
    )

    ioc_table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),HexColor("#0B5ED7")),

        ("TEXTCOLOR",(0,0),(-1,0),colors.white),

        ("GRID",(0,0),(-1,-1),0.5,colors.grey),

        ("BOTTOMPADDING",(0,0),(-1,-1),8),

        ("TOPPADDING",(0,0),(-1,-1),8)

    ]))

    story.append(ioc_table)

    story.append(Spacer(1,20))

    # ==================================
    # MITRE ATT&CK
    # ==================================

    story.append(
        Paragraph(
            "MITRE ATT&CK Mapping",
            heading
        )
    )

    mitre_data = [

        ["Technique ID","Technique","Tactic"]

    ]

    for attack in results["MITRE"]:

        mitre_data.append([

            attack["id"],

            attack["technique"],

            attack["tactic"]

        ])

    mitre_table = Table(
        mitre_data,
        colWidths=[90,220,140]
    )

    mitre_table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),HexColor("#0B5ED7")),

        ("TEXTCOLOR",(0,0),(-1,0),colors.white),

        ("GRID",(0,0),(-1,-1),0.5,colors.grey),

        ("BOTTOMPADDING",(0,0),(-1,-1),8),

        ("TOPPADDING",(0,0),(-1,-1),8)

    ]))

    story.append(mitre_table)

    story.append(Spacer(1,20))
    
    doc.build(story)

    return filename
