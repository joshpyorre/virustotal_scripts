import requests
import json
import datetime
import csv
import base64
import argparse
from urllib.parse import urlparse

parser = argparse.ArgumentParser(description="Scan URLS with VirusTotal API.")
parser.add_argument("input_file", help="File containing list of URLs")
parser.add_argument("--apikey", default="your_vt_api_key.txt", help="Path to your VirusTotal API key file")

args = parser.parse_args()

def save_json_file_for_troubleshooting(data):
    with open('vt_url_scan_results.json', 'w') as file:
        json.dump(data, file, indent=2)

def process_vt_results(data):
    for k, v in data.items():
        vt_results = {}

    try:
        attrs = v['attributes']
        last_analysis_stats = attrs.get('last_analysis_stats', {})
        first_submission_date = datetime.datetime.fromtimestamp(
            attrs.get('first_submission_date', 0)
        ).strftime('%Y-%m-%d %H:%M:%S')

        vt_results['url'] = attrs.get('url', 'none')

        vt_results['suspicious (VT Vendors)'] = last_analysis_stats.get('suspicious', 0)
        vt_results['harmless (VT Vendors)'] = last_analysis_stats.get('harmless', 0)
        vt_results['undetected (VT Vendors)'] = last_analysis_stats.get('undetected', 0)
        vt_results['malicious (VT Vendors)'] = last_analysis_stats.get('malicious', 0)

        vt_results['first_submission_date'] = first_submission_date

        # Clean up optional
        vt_results.pop('timeout', None)
        vt_results.pop('viewport', None)

        return vt_results
    except Exception as e:
        print(f"Error parsing VT results: {e}")
        return None

def scan_urls_with_vt(input_file, apikey_path):
    with open(apikey_path, 'r') as f:
        key = f.read().strip()

    headers = {
        "x-apikey": key
    }

    vt_results = []

    with open(input_file, 'r') as file:
        lines = [line.split('\t')[0].strip() for line in file if line.strip()]
    
    for url in lines:
        print(f"URL: {url}")

        base64_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vturl = f'https://www.virustotal.com/api/v3/urls/{base64_url}'

        response = requests.get(vturl, headers=headers)

        if response.status_code != 200:
            print(f"Error querying {url}: {response.status_code}")
            continue

        data = response.json()

        if 'data' not in data:
            print(f"Invalid response for URL: {url}")
            continue

        result = process_vt_results(data)
        if result:
            vt_results.append(result)

    return vt_results

def main():

    results = scan_urls_with_vt(args.input_file, args.apikey)

    if not results:
        print("No results to write.")
        return

    filename = args.input_file.split('.')[0] + '_VT_SCAN_RESULTS.csv'
    fieldnames = ['url', 'first_submission_date', 'suspicious (VT Vendors)',
                  'harmless (VT Vendors)', 'undetected (VT Vendors)', 'malicious (VT Vendors)']

    with open(filename, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            writer.writerow(item)

    print(f"Done. Results written to: {filename}")

if __name__ == "__main__":
    main()