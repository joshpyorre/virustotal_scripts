import requests
import json
import datetime
import csv
import argparse
import tldextract

parser = argparse.ArgumentParser(description="Scan domains with VirusTotal API.")
parser.add_argument("input_file", help="File containing list of reversed domains (reversed because we often work with domains from our feed lists, which contains FQDNS reversed)")
parser.add_argument("--apikey", default="your_vt_api_key.txt", help="Path to your VirusTotal API key file")

args = parser.parse_args()

def reverse_domain(rdomain):
    if rdomain:
        rdomain = rdomain.rstrip('\n')
        parts = rdomain.rstrip('.').split('.')
        return '.'.join(reversed(parts))

def save_json_file_for_troubleshooting(data):
    with open('vt_domain_scan_results.json', 'w') as file:
        json.dump(data, file, indent=2)

def process_vt_domain_results(data, domain):
    try:
        attributes = data['data']['attributes']
    except KeyError:
        print(f"Missing 'attributes' for domain: {domain}")
        return None

    stats = attributes.get('last_analysis_stats', {})
    timestamp = attributes.get('creation_date') or attributes.get('last_analysis_date') or 0
    first_submission_date = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    categories = attributes.get('categories', {})
    unique_categories = list(set(categories.values()))
    category_string = ", ".join(sorted(unique_categories))

    vt_results = {
        'domain': domain,
        'first_submission_date': first_submission_date,
        'suspicious (VT Vendors)': stats.get('suspicious', 0),
        'harmless (VT Vendors)': stats.get('harmless', 0),
        'undetected (VT Vendors)': stats.get('undetected', 0),
        'malicious (VT Vendors)': stats.get('malicious', 0),
        'categories': category_string
    }

    return vt_results

def scan_domains_with_vt(input_file, apikey_path):
    with open(apikey_path, 'r') as f:
        key = f.read().strip()

    headers = {
        "x-apikey": key
    }
    vt_results = []

    with open(input_file, 'r') as file:
        lines = [line.strip() for line in file if line.strip()]

    for rdomain in lines:
        domain = reverse_domain(rdomain)
        extracted = tldextract.extract(domain)
        domain = ".".join(part for part in [extracted.subdomain, extracted.domain, extracted.suffix] if part)
        print(f"Querying: {domain}")

        vturl = f'https://www.virustotal.com/api/v3/domains/{domain}'
        response = requests.get(vturl, headers=headers)

        if response.status_code != 200:
            print(f"Error querying {domain}: {response.status_code}")
            continue

        data = response.json()

        # Uncomment if you'd like to troubleshoot
        # save_json_file_for_troubleshooting(data)

        result = process_vt_domain_results(data, domain)
        if result:
            vt_results.append(result)

    return vt_results

def main():

    results = scan_domains_with_vt(args.input_file, args.apikey)

    if not results:
        print("No results to write.")
        return

    output_file = args.input_file.split('.')[0] + '_VT_DOMAIN_SCAN_RESULTS.csv'
    fieldnames = ['domain', 'first_submission_date', 'suspicious (VT Vendors)',
                  'harmless (VT Vendors)', 'undetected (VT Vendors)', 'malicious (VT Vendors)',
                  'categories']

    with open(output_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            writer.writerow(item)

    print(f"Done. Results written to: {output_file}")

if __name__ == "__main__":
    main()