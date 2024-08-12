import requests 
import time
import base64

# Enter the url's you want scanned within the list
list = [
]

api_key = '{your_api_key_here}'

# For loop to go through every url in the list
for site in list:

    # Encode and strip the url so it complies with Virus Total's query format
    encoded_url = base64.urlsafe_b64encode(site.encode()).decode().strip("=")
    url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'
    headers = {'x-apikey': api_key}

    # Get request to the Virus Total API
    report = requests.get(url, headers=headers)

    # Parse the JSON report
    response_json = report.json()

    # Extract the number of malicious detections from the response
    positives = response_json.get("list", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)

    # Write the results to 'vt_results.txt' based on the number of malicious detections
    with open('vt_results.txt', 'a') as vt:
        if positives <= 0:
            vt.write(f"{site} -\tNOT MALICIOUS\n")
        elif 1 <= positives <= 3:
            vt.write(f"{site} -\tMAYBE MALICIOUS\n")
        elif positives >= 4:
            vt.write(f"{site} -\tMALICIOUS\n")
        else:
            vt.write(f"{site} -\tERROR IN ANALYSIS\n")

    # Sleep for 15 seconds to respect the API response rate
    time.sleep(15)
