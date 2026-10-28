"""PDF reports generated from saved results only."""
from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,KeepTogether
def build_report(assessment,sample=False):
    out=BytesIO(); doc=SimpleDocTemplate(out,pagesize=letter,rightMargin=48,leftMargin=48,topMargin=54,bottomMargin=48,title="VulnAssess Report"); styles=getSampleStyleSheet(); body=ParagraphStyle("body",parent=styles["BodyText"],leading=14,spaceAfter=5); story=[]; esc=lambda v:escape(str(v or ""))
    story += [Paragraph("VulnAssess - Security Assessment Report",styles["Title"])]
    if sample: story.append(Paragraph("SAMPLE FIXTURE DATA - NOT A REAL ASSESSMENT",styles["Heading2"]))
    story += [Paragraph(f"Report ID: {esc(assessment.report_id)}",body),Paragraph(f"Target: {esc(assessment.target)} | Type: {esc(assessment.assessment_type)}",body),Paragraph(f"Started: {esc(assessment.started_at)} | Status: {esc(assessment.status)}",body),Spacer(1,12),Paragraph("Scope and limitations",styles["Heading2"]),Paragraph("Authorized target only. Safe TCP discovery and/or single-response HTTP header checks; no exploitation, brute force, crawling, or destructive checks. Results require human validation.",body)]
    severities=["Critical","High","Medium","Low","Informational"]; counts={s:sum(f.severity==s for f in assessment.findings) for s in severities}
    story += [Paragraph("Executive summary",styles["Heading2"]),Paragraph(f"Saved observations: {len(assessment.findings)} findings and {len(assessment.services)} open services. Severity totals: "+" | ".join(f"{s}: {counts[s]}" for s in severities),body)]
    if assessment.services:
        story.append(Paragraph("Discovered services",styles["Heading2"])); data=[["Host","Port","Service","Product / version"]]+[[esc(s.host),str(s.port),esc(s.service_name),esc(" ".join(filter(None,[s.product,s.version])))] for s in assessment.services]; table=Table(data,colWidths=[120,42,100,190],repeatRows=1); table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16365c")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#eef3f8")])])); story.append(table)
    for sev in severities:
        for f in [x for x in assessment.findings if x.severity==sev]:story.append(KeepTogether([Paragraph(sev+" - "+esc(f.check_name),styles["Heading3"]),Paragraph(f"ID: {esc(f.finding_uid)} | Status: {esc(f.status)} | Confidence: {esc(f.confidence)}",body),Paragraph("Evidence: "+esc(f.evidence),body),Paragraph("Rationale: "+esc(f.rationale),body),Paragraph("Impact: "+esc(f.impact),body),Paragraph("Remediation: "+esc(f.remediation),body),Spacer(1,6)]))
    story += [Spacer(1,12),Paragraph("Methodology and disclaimer",styles["Heading2"]),Paragraph("VulnAssess records automated observations from selected safe checks. An open port or missing header is a configuration observation, not proof of vulnerability or exploitability. Validate findings with an authorized human reviewer.",body)]
    def footer(canvas,doc):canvas.saveState(); canvas.setFont("Helvetica",8); canvas.setFillColor(colors.grey); canvas.drawString(48,28,"VulnAssess - Confidential authorized assessment"); canvas.drawRightString(564,28,f"Page {doc.page}"); canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer); return out.getvalue()
