import requests
import json
from api import api_key

soft_list = [
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version": "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version": "2.4.29"},
    {"Program": "DjVu Reader", "Version": "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version": "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version": "61.0.1"}
]

def software_testing(soft_list):
    url = "https://vulners.com/api/v3/burp/softwareapi/"
    headers = {"Content-Type": "application/json"}
    soft_without_vuln = []
    soft_with_cve = []
    list_of_cve = []
    for soft in soft_list:
        program_name = soft["Program"]
        version = soft["Version"]
        data = {
            "software": program_name,
            "version": version,
            "type": "software",
            "maxVulnerabilities": 50,
            "apiKey": api_key
        }       
        response = requests.post(url, headers=headers, json=data)
        json_data = response.json()["data"]
        search = json_data.get("search")
        if search == None:
            soft_without_vuln.append(program_name)
        else:
            soft_with_cve.append(program_name)
            print("\nVulnerabilities of the " + program_name + " program:\n")
            for vuln in search:
                if "CVE" in vuln["id"]:
                    print(vuln["id"])
                
    print("\nThere are no vulnerabilities in these programs:") 
    for program in soft_without_vuln:
        for soft in soft_list:
            if program == soft["Program"]:
                print("Program: " + soft["Program"] + ", version: " + soft["Version"] + " - no vulnerabilities found")
    
    print("\nVulnerabilities have been found in these programs:")
    for program in soft_with_cve:
        for soft in soft_list:
            if program == soft["Program"]:
                print("Program: " + soft["Program"] + ", version: " + soft["Version"])

software_testing(soft_list)