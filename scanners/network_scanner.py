import nmap

def run_network_scan(app):
    nm = nmap.PortScanner()
    nm.scan('127.0.0.1', '22-443')  # Scanning localhost as an example
    app.insert_text(f"Network Scan Result: {nm.csv()}\n")
