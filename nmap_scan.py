import nmap

class NetworkScanner:
    def __init__(self, target_ip, scan_type="-sS", port_range="1-1024"):
        """
        Initialize the NetworkScanner with a target IP, scan type, and port range.
        """
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_range = port_range
        self.nm = nmap.PortScanner()

    def perform_scan(self):
        """ Perform a network scan based on the scan type and target IP """
        print(f"Starting scan on {self.target_ip} with scan type {self.scan_type} on port range {self.port_range}...")
        try:
            # Perform the scan with version detection (add -sV flag)
            self.nm.scan(self.target_ip, self.port_range, self.scan_type)
            return self.nm
        except Exception as e:
            print(f"An error occurred during the scan: {e}")
            return None

    def display_scan_results(self, nm):
        """ Display the scan results in a readable format. """
        print(f"\nScan results for {self.target_ip}:")
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', 'unknown')
                    version = nm[host][proto][port].get('version', 'unknown')
                    print(f"Port: {port}, State: {state}, Service: {service}, Version: {version}")
                    yield service, version  # Yield service and version for CVE lookup
