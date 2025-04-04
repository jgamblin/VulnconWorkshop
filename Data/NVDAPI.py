import requests
import json
from requests.adapters import HTTPAdapter, Retry
from json.decoder import JSONDecodeError
import time
import os


cve_array = []
pagesize = 2000
startindex = 0

session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
session.mount('http:s//', HTTPAdapter(max_retries=retries))

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'apiKey': 'Get API KEY HERE: https://nvd.nist.gov/developers/request-an-api-key'
}

response = session.get('https://services.nvd.nist.gov/rest/json/cves/2.0/?startIndex=0&resultsPerPage=1', headers=headers)
if response.status_code == 200:
    json_data = response.json()
    total_cves = json_data.get('totalResults', 0)
    print(total_cves)
else:
    print(f"Failed to fetch total CVEs. HTTP Status Code: {response.status_code}")
    exit(1)

while startindex < total_cves:
    response = session.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage={pagesize}&startIndex={startindex}", headers=headers)
    try:
        cves = json.loads(response.content.decode('utf-8'))
        for i in cves['vulnerabilities']:
            cve_array.append(i)
        startindex = startindex + pagesize
        print(startindex)
    except JSONDecodeError as e:
        print("JSONDecodeError occurred. Retrying...")
        time.sleep(10)
        continue
    except TypeError as e:
        print("TypeError occurred. Retrying...")
        time.sleep(10)
        continue

jsonString = json.dumps(cve_array)
with open("nvd.jsonl", "w") as jsonFile:
    jsonFile.write(jsonString)