import requests
import re
from utils import standardize_service_name

def check_cve(service_name, version):
    """ Query the CVE API to check for vulnerabilities. """
    if service_name == 'unknown' or version == 'unknown':
        print(f"Skipping CVE check for {service_name} version {version}")
        return

    # Standardize service names for the CVE API
    service_name = standardize_service_name(service_name)

    # If no version detected or an invalid service name, skip
    if service_name is None:
        print(f"Service {service_name} is not valid for CVE lookup.")
        return

    # Clean the version string (remove non-alphanumeric characters, e.g., p1)
    cleaned_version = re.sub(r'[^0-9\.]', '', version)
    print(f"Checking CVEs for {service_name} version {cleaned_version}")
    
    # Construct the API URL for CVE search
    url = f"https://cve.circl.lu/api/search/{service_name}/{cleaned_version}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()

        # Parse the response
        cve_results = response.json()

        if not cve_results:
            print(f"No vulnerabilities found for {service_name} version {cleaned_version}")
        else:
            print(f"Vulnerabilities found for {service_name} version {cleaned_version}:")
            for entry in cve_results:
                print(f"CVE ID: {entry['id']}")
                print(f"Summary: {entry['summary']}")
                print("-----")
    
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")
