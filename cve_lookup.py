import requests

def cve_lookup_nvd(service, version, api_key):
    print(f"Performing CVE lookup for service: {service}, version: {version}")
    print(f"Using API key: {api_key}")

    # Simplified URL using only cvssV3Severity=HIGH
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH"
    headers = {
        'apiKey': api_key  # API key passed as a parameter
    }

    try:
        print(f"Making request to: {url}")
        response = requests.get(url, headers=headers)
        print(f"Response status code: {response.status_code}")

        # Raise an HTTPError for bad responses
        response.raise_for_status()

        # Parse JSON response
        data = response.json()
        print(f"Data received from NVD API: {data}")

        if 'vulnerabilities' in data:
            print(f"Found CVEs with HIGH severity:")
            for vuln in data['vulnerabilities']:
                cve = vuln['cve']
                print(f"CVE ID: {cve['id']}")
                description = cve['descriptions'][0]['value'] if cve['descriptions'] else "No description available.."
                print(f"Description: {description}")
                print("-----")

        cve_count = len(data['vulnerabilities'])
        if cve_count > 10:
            with open("vuln_results.txt", "w") as f:
                for vuln in data["vulnerabilities"]:
                    cve = vuln["cve"]
                    description = cve['descriptions'][0]['value'] if cve ['descriptions'] else "No description available.."
                    f.write(f"CVE ID: {cve['id']}\nDescription: {description}\n-----\n")
                print(f'Results saved to vuln_results.txt')
        else:
            for vuln in data['vulnerabilities']:
                cve = vuln['cve']
                print(f"CVE ID: {cve['id']}")
                description = cve['description'][0]['value'] if cve['description'] else "No descrpition available.."
                print(f"Description: {description}")
                print("----")
            else:
                print(f"No CVEs found for {service} version {version}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while trying to fetch CVEs: {e}")
    except Exception as err:
        print(f"An unexpected error occurred: {err}")
