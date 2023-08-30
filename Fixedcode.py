import whois
import validators
import requests
import json
import socket
from config import api_key
from urllib.parse import urlparse 

#https://docs.python.org/3/library/urllib.parse.html
def extract_root_domain(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc.startswith("www."):
        return parsed_url.netloc[4:]
    else:
        return parsed_url.netloc

dm = input("Input domain name: ")

dm = input("Input domain name: ")

def domain_lookup(dm):
    if validators.domain(dm):
        try:
            dm_info = whois.whois(dm)
            return dm_info
        except Exception as e:
            return f"{dm} lookup failed: {e}"
    else:
        return "Enter a valid domain"

if not validators.domain(dm):
    print("Enter a valid domain")
else:
    lookup_results = domain_lookup(dm)

    if "creation_date" in lookup_results:
        try:
            res = socket.gethostbyname(dm)

            url = 'https://api.abuseipdb.com/api/v2/check'
            
            querystring = {
                'ipAddress': res,
                'maxAgeInDays': '90'
            }

            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }

            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            try:
                response.raise_for_status()  # Raises an HTTPError if the response status code is not successful

                data = response.json()

                Abuse_report_history_isPublic = data["data"]["isPublic"]
                Abuse_report_history_totalreports = data["data"]["totalReports"]
                Abuse_report_history_abuseConfidenceScore = data["data"]["abuseConfidenceScore"]

                abuse_report_status = "Safe"
                if Abuse_report_history_abuseConfidenceScore > 75:
                    abuse_report_status = "Unsafe"

                http_status_code = response.status_code

                print("Domain entered: ", dm)

                if isinstance(lookup_results.creation_date, list):
                    creation_date = lookup_results.creation_date[0]
                else:
                    creation_date = lookup_results.creation_date

                if creation_date:
                    print("Domain created at: ", str(creation_date))

                if isinstance(lookup_results.expiration_date, list):
                    expiration_date = lookup_results.expiration_date[0]
                else:
                    expiration_date = lookup_results.expiration_date

                if expiration_date:
                    print("Domain expires at: ", str(expiration_date))

                print("Website status code: ", http_status_code)
                print("Abuse report history isPublic: ", Abuse_report_history_isPublic)
                print("Abuse report history totalReports: ", Abuse_report_history_totalreports)
                print("Abuse report history abuseConfidenceScore: ", Abuse_report_history_abuseConfidenceScore)
                print("Abuse report status: ", abuse_report_status)
            except requests.exceptions.RequestException as req_ex:
                print(f"API request error: {req_ex}")
            except json.JSONDecodeError as json_ex:
                print(f"JSON decoding error: {json_ex}")
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print(f"Domain {dm} lookup failed, domain is valid, but not registered")
