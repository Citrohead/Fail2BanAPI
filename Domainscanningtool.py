import whois
import validators # pip install validators
import requests
import json
import socket
from config import api_key

dm = input("Input domain name: ")

def domain_lookup(dm):

    if validators.domain(dm): # Check if Domain is Valid

        try:
            dm_info =  whois.whois(dm) # Get Domain Info
            return dm_info

        except:
            return f"{dm} is not registered"

    else:
        return f"Enter a valid domain"

lookup_results = domain_lookup(dm)


# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/check'
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
#decodedResponse = json.loads(response.text)
#print( json.dumps(decodedResponse, sort_keys=True, indent=4) )

Abuse_report_history_isPublic = data["data"]["isPublic"]
Abuse_report_history_totalreports = data["data"]["totalReports"]
Abuse_report_history_abuseConfidenceScore = data["data"]["abuseConfidenceScore"]
#75%-100% is the recommended range for denial of service. https://docs.abuseipdb.com/?python#reports-parameters
abuse_report_status = "Safe"
if Abuse_report_history_abuseConfidenceScore > 75:
    abuse_report_status = "Unsafe"

#Website status code
http_status_code = response.status_code

print("Domain entered: ", dm)
print("Domain created at: ", str(lookup_results.creation_date[0] ))
print("Domain expires at: ", str(lookup_results.expiration_date[0] ))
print("Website status code: ", http_status_code)
print("Abuse report history isPublic: ", Abuse_report_history_isPublic)
print("Abuse report history totalReports: ", Abuse_report_history_totalreports)
print("Abuse report history abuseConfidenceScore: ", Abuse_report_history_abuseConfidenceScore)
print("Abuse report status: ", abuse_report_status)
