import pdfkit

def generate_report(scan_results, output_path="report.pdf"):
    # Here we can generate a PDF report
    html = f"""
    <html>
    <body>
        <h1>Scan Results</h1>
        <p>{scan_results}</p>
    </body>
    </html>
    """
    pdfkit.from_string(html, output_path)
    print(f"Report generated at {output_path}")
