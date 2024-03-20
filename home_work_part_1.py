import zipfile
import os
import requests
import json
from api import api_key

def unzip(file_path):
    path = "extracted_files"

    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall(path, pwd=bytes('netology', 'utf-8'))
    return path

def count_html_files(dir_path):
    html_files_in_dir = []

    for file in os.listdir(dir_path):
        if os.path.splitext(file)[1] == '.html':
            html_files_in_dir.append(file)

    if len(html_files_in_dir) > 1:
        print("Too many files with the extension html. The program can only work with a single HTML file.")
        exit()
    elif len(html_files_in_dir) < 1:
        print("There are no HTML files in the directory.")
        exit()
    else:
        target_file = os.path.join(dir_path,html_files_in_dir[0])
        print(target_file)
        return os.path.abspath(target_file)

def file_analysis(target_file_path):
    api_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    with open(target_file_path, "rb") as file:
        files = {"file": (target_file_path, file)}
        response = requests.post(api_url, headers=headers, files=files)
        get_url = response.json()["data"]["links"]["self"]
        analise_result = requests.get(get_url, headers=headers)
        return analise_result.json()

def behaviour_summary(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}/behaviour_summary"
    headers = {"accept": "application/json", "x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json()

# Write 'output_type="all"' to display the full analysis result; otherwise, a summarized result will be shown.
def file_analise(file_path, output_type="less"):

    # Stage 1. Unpacking an archive.
    dir_for_extracted_files = unzip(file_path)
    # Checking the number of HTML files.
    target_file = count_html_files(dir_for_extracted_files)

    # Stage 2. Submitting a file for analysis.
    analise_result = file_analysis(target_file)

    # Stage 3. Displaying the analysis result.
    if output_type == 'all':
        print(json.dumps(analise_result, indent=4))
    else:
        print(json.dumps(analise_result["data"]["attributes"]["stats"], indent=4))

    # Stage 4. Printing antivirus programs list.
    print("\nThe list of antivirus programs that detected threats:")
    antivirus_list = []
    for key in analise_result["data"]["attributes"]["results"].keys():
        if analise_result["data"]["attributes"]["results"][key]["result"] != None:
            antivirus_list.append(key)
            print(key, ': ', analise_result["data"]["attributes"]["results"][key]["result"])
    # Comparison of the results.
    print("\nThe following antivirus programs from the list detected a threat:")
    for antivirus in antivirus_list:
        if antivirus == "Fortinet" or antivirus == "McAfee" or antivirus == "Yandex" or antivirus == "Sophos":
            print(antivirus)

    # Additional tasks
    file_hash = analise_result["meta"]["file_info"]["sha256"]
    behaviour_data = behaviour_summary(file_hash)["data"]
    print("\nMitre_attack_techniques:", json.dumps(behaviour_data["mitre_attack_techniques"], indent=4), "\n\nTags:", behaviour_data["tags"]) 
    print("\nList of domain names and IP addresses:")
    for dns_lookup in behaviour_data["dns_lookups"]:
        print(json.dumps(dns_lookup, indent=4))

file_analise("protected_archive.zip")
