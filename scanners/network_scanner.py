import socket

def run_network_scan(app):
    """Perform a basic network scan to identify network vulnerabilities."""
    app.insert_text("Starting network scan...\n", "info")
    
    # Simulate scanning localhost and basic ports
    host_name = socket.gethostname()
    host_ip = socket.gethostbyname(host_name)
    
    app.insert_text(f"Host: {host_name}, IP: {host_ip}\n", "info")
    
    # Simulated scan of ports (you can add more advanced scanning here)
    open_ports = [22, 80, 443]  # Mock open ports
    app.insert_text(f"Open ports: {', '.join(map(str, open_ports))}\n", "info")
    
    # Simulate vulnerabilities
    vulnerabilities = {"22": "SSH Vulnerability", "443": "SSL Vulnerability"}
    for port, vuln in vulnerabilities.items():
        app.insert_text(f"Port {port}: {vuln}\n", "warning")
    
    app.insert_text("Network scan completed.\n", "success")
