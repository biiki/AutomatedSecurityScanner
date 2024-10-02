import requests
import re
from utils import standardize_service_name
from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv('NVD_API_KEY')

def cve_lookup(service, version):
    url = f"https://cve.circl.lu/api/search/{service}/{version}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data:
                print(f"Found a CVE database match for {service}, version {version}:")
            else:
                print(f"No CVE matches found for {service}, version {version}.")
        else:
            print(f"HTTP error occurred: {response.status_code} - {response.reason}")
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while trying to fetch CVEs: {e}")


def cve_lookup_nvd(service, version, api_key):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}%20{version}"
    headers = {
        'apiKey': api_key  # API key is now passed as a parameter
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if 'result' in data and data['result']['CVE_Items']:
                print(f"Found a CVE match for {service} version {version}:")
                # Process and print CVE items
                for cve_item in data['result']['CVE_Items']:
                    print(f"CVE ID: {cve_item['cve']['CVE_data_meta']['ID']}")
                    print(f"Description: {cve_item['cve']['description']['description_data'][0]['value']}")
            else:
                print(f"No CVEs found for {service} version {version}")
        else:
            print(f"HTTP error occurred: {response.status_code} - {response.reason}")
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while trying to fetch CVEs: {e}")

# Standardizing service names for the CVE API
def standardize_service_and_version(service, version):
    service_name = standardize_service_name(service)
    
    # If no valid service name, return none
    if service_name is None:
        print(f"Service {service_name} is not valid for CVE lookup.")
        return None, None
    
    # Clean the version string to remove any nonnumeric chars
    cleaned_version = re.sub(r'[^0-9\.]', '', version)
    
    return service_name, cleaned_version

