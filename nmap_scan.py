import nmap

class NetworkScanner:
    def __init__(self, target_ip, scan_type="-sS", port_range="1-1024"):
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_range = port_range

    def perform_scan(self):
        scanner = nmap.PortScanner()
        print(f"Starting scan on {self.target_ip} with scan type {self.scan_type} on port range {self.port_range}...")
        
        try:
            scanner.scan(self.target_ip, self.port_range, arguments=self.scan_type)
            return scanner
        except Exception as e:
            print(f"An error occurred while scanning: {e}")
            return None

    def display_scan_results(self, nm):
        print(f"Scan results for {self.target_ip}:")
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port].get('version', '')
                    print(f"Port: {port}, State: {nm[host][proto][port]['state']}, Service: {service}, Version: {version}")
                    yield service, version
