from fpdf import FPDF

def generate_report():
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="BenardAI Scan Report", ln=True, align="C")

    # Add dummy content (replace with actual results)
    pdf.cell(200, 10, txt="Scan Results:", ln=True)
    pdf.cell(200, 10, txt="File Scan: Malicious", ln=True)
    pdf.cell(200, 10, txt="Network Scan: No vulnerabilities", ln=True)

    pdf.output("scan_report.pdf")
