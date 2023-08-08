import whois
import validators # pip install validators
import requests
import json
import socket
from config import api_key

dm = input("Input domain name: ")

def domain_lookup(dm):
    if validators.domain(dm):  # Check if Domain is Valid
        try:
            dm_info = whois.whois(dm)  # Get Domain Info
            return dm_info
        except:
            return f"{dm} is not registered"
    else:
        return f"Enter a valid domain"

# Check if the domain is valid before proceeding
if not validators.domain(dm):
    print("Enter a valid domain")
else:
    lookup_results = domain_lookup(dm)

    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    # Check if the domain lookup was successful before proceeding
    if "creation_date" in lookup_results:
        res = socket.gethostbyname(dm)
    
        querystring = {
            'ipAddress': res,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        data = response.json()

        # Formatted output
        # decodedResponse = json.loads(response.text)
        # print( json.dumps(decodedResponse, sort_keys=True, indent=4) )

        Abuse_report_history_isPublic = data["data"]["isPublic"]
        Abuse_report_history_totalreports = data["data"]["totalReports"]
        Abuse_report_history_abuseConfidenceScore = data["data"]["abuseConfidenceScore"]
        # 75%-100% is the recommended range for denial of service. https://docs.abuseipdb.com/?python#reports-parameters
        abuse_report_status = "Safe"
        if Abuse_report_history_abuseConfidenceScore > 75:
            abuse_report_status = "Unsafe"

        # Website status code
        http_status_code = response.status_code

        print("Domain entered: ", dm)

        # Handling creation_date when whois shows not in list
        if isinstance(lookup_results.creation_date, list):
            creation_date = lookup_results.creation_date[0]
        else:
            creation_date = lookup_results.creation_date

        if creation_date:
            print("Domain created at: ", str(creation_date))

        # Handling expiration_date when whois shows not in list
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
    else:
        print(f"Domain {dm} lookup failed, domain is valid, but not registered")
