import argparse
from nmap_scan import NetworkScanner
from cve_lookup import check_cve

def select_scan_type():
    print("Select a scan type:")
    print("1. SYN Scan (-sS)")
    print("2. TCP Scan (-sT)")
    print("3. UDP Scan (-sU)")
    print("4. OS Detection (-O)")
    print("5. Custom Scan")

    choice = input("Enter the number of your choice: ")

    if choice == "1":
        return "-sS"
    elif choice == "2":
        return "-sT"
    elif choice == "3":
        return "-sU"
    elif choice == "4":
        return "-O"
    elif choice == "5":
        custom_scan = input("Enter your custom nmap scan option (e.g., -sP, -sN): ")
        return custom_scan
    else:
        print("Invalid choice, defaulting to SYN scan.")
        return "-sS"

def main():
    parser = argparse.ArgumentParser(description="Network Scanner with Vulnerability Detection")
    
    # Positional argument: target IP or domain
    parser.add_argument('target', type=str, help="The target IP or domain to scan")
    
    # Optional argument: port range (default is 1-1024)
    parser.add_argument('--ports', type=str, default='1-1024', help="Specify the port range to scan (default is 1-1024)")

    # Optional argument: scan type (can skip the interactive menu)
    parser.add_argument('--scan-type', type=str, default=None, help="Specify the scan type (e.g., -sS for SYN scan, -sT for TCP scan, -O for OS detection)")

    args = parser.parse_args()

    # If scan type is provided via argparse, use it
    if args.scan_type:
        scan_type = args.scan_type
    else:
        # If no scan type provided, fall back to interactive menu
        scan_type = select_scan_type()

    # Create the NetworkScanner instance
    scanner = NetworkScanner(target_ip=args.target, scan_type=scan_type, port_range=args.ports)
    
    # Perform the scan
    nm = scanner.perform_scan()
    
    if nm:
        # Display scan results and run CVE checks
        for service, version in scanner.display_scan_results(nm):
            check_cve(service, version)

if __name__ == "__main__":
    main()
