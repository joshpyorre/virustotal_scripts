# VirusTotal Scanner

This project contains two Python scripts to scan **domains** or **URLs** using the [VirusTotal API v3](https://developers.virustotal.com/reference).

For vt_domain_scan.py, run like this: python3 vt_domain_scan.py domains.txt (where domains are one domain per line)
For vt_url_scan.py, run like this: python3 vt_url_scan.py url.txt (where domains are one url per line)

Note: The domain script has a function to reverse domains (from com.google. to google.com) because we often work with domains from our feed lists, which contains the FQDNS reversed. If you have a list of domains that are normal, then you can modify the lines that do that (towards the bottom of the script).

## 🔧 Requirements

- Python 3.6+
- `requests`
- `tldextract`

Adjust the path of your API key. It should be your virustotal API key on only one line in a text file. No need to specify it as "key=yourapikey". Just paste the key directly in the file.

Install dependencies with:

```bash
pip install -r requirements.txt