import whois
import validators
import requests
import json
import socket
from config import api_key
from urllib.parse import urlparse

def extract_root_domain(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc.startswith("www."):
        return parsed_url.netloc[4:]
    else:
        return parsed_url.netloc

def get_domain_from_user():
    dm = input("Input domain name: ")
    return extract_root_domain(dm)

def get_domain_info(dm):
    try:
        dm_info = whois.whois(dm)
        return dm_info
    except Exception as e:
        return f"{dm} lookup failed: {e}"

def is_valid_domain(dm):
    return validators.domain(dm)

def get_abuse_report(ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}

    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()

        return response.json()["data"]
    except requests.exceptions.RequestException as req_ex:
        raise RuntimeError(f"API request error: {req_ex}")
    except json.JSONDecodeError as json_ex:
        raise RuntimeError(f"JSON decoding error: {json_ex}")

def print_domain_info(dm, lookup_results, http_status_code, abuse_report_data):
    print("Domain entered: ", dm)

    creation_date = lookup_results.creation_date[0] if isinstance(lookup_results.creation_date, list) else lookup_results.creation_date
    if creation_date:
        print("Domain created at: ", str(creation_date))

    expiration_date = lookup_results.expiration_date[0] if isinstance(lookup_results.expiration_date, list) else lookup_results.expiration_date
    if expiration_date:
        print("Domain expires at: ", str(expiration_date))

    print("Website status code: ", http_status_code)
    print("Abuse report history isPublic: ", abuse_report_data["isPublic"])
    print("Abuse report history totalReports: ", abuse_report_data["totalReports"])
    print("Abuse report history abuseConfidenceScore: ", abuse_report_data["abuseConfidenceScore"])

    abuse_report_status = "Safe" if abuse_report_data["abuseConfidenceScore"] <= 75 else "Unsafe"
    print("Abuse report status: ", abuse_report_status)

def main():
    dm = get_domain_from_user()

    if not is_valid_domain(dm):
        print("Enter a valid domain")
    else:
        lookup_results = get_domain_info(dm)

        if "creation_date" in lookup_results:
            try:
                ip_address = socket.gethostbyname(dm)
                abuse_report_data = get_abuse_report(ip_address)

                print_domain_info(dm, lookup_results, 200, abuse_report_data)
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print(f"Domain {dm} lookup failed, domain is valid, but not registered")

if __name__ == "__main__":
    main()
