import requests
import re
from google import genai
import json


# This function interacts with the ipinfo.io API
def IPinfo(ip):
    data = "Do not include IP information in report"

    token = ''

    url = f'https://ipinfo.io/{ip}?token={token}'

    response = requests.get(url)

    if response.status_code == 200:
        data = response.text
        #print(type(data))
        return data
    else:
        print(f'Error: {response.status_code}')

# This function interacts with the AbuseIPdb.com API 
def abuseIPdb(ip):
        # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': f'{ip}',
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': ''
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    return json.dumps(decodedResponse, sort_keys=True, indent=4)
    
#This function interacts with the VirusTotal.com API
def ProcessInfo(sig):
    Process = "N/A"
    Signers = "N/A"
    FtypeData = "N/A"
    ratio = "N/A"


    url = f'http://www.virustotal.com/api/v3/files/{sig}'

    headers = {
        "x-apikey":""

        }

    response = requests.get(url, headers=headers)

    # Sample log as a string
    log = response.text
    print(log)

    # Regex to find the "names" field
    process_name_regex = r'"names":\s*\["(.*?)"\]'    
    process_name_match = re.search(process_name_regex, log)

    file_type_regex = r'"type_description":\s*"(.*?)"'
    file_type_match = re.search(file_type_regex, log)

    # Regex to find the "signers details" field
    signers_regex = r'"signers":\s*"(.*?)"'
    signers_match = re.search(signers_regex, log, re.DOTALL)


    pattern = r'"malicious": (\d+),.*"undetected": (\d+)'
    match = re.search(pattern, log)

    if match:
        # Extract the values
        malicious = int(match.group(1))
        undetected = int(match.group(2))
        
        # Compute the ratio
        ratio = f"{malicious}/{malicious + undetected}"
    else:
        print("Ratio not found.")
    

    # Display the results
    if process_name_match:
        Process = process_name_match.group(1)
    else:
        print("Process Name not found")

    if signers_match:
        Signers = signers_match.group(1)
    else:
        print("Signers Information not found")

    if file_type_match:
        FtypeData = file_type_match.group(1)
    else:
        print("File Type Information not found")
        
    return Process, Signers, FtypeData, sig, ratio

def google_api_name(fName, ip):
    client = genai.Client(api_key="")
    response = client.models.generate_content(model="gemini-2.0-flash",
        contents=f'''
        You are an advanced reporting writing AI designed to generate professional reports for security investigations based on provided input.

        1.  **IP Information Formatting:** You will receive a set of IP information. Format this data accurately and consistently. **Include only fields that contain data.** Use bullet points or tables where appropriate. Ensure the formatting is clear, organized, and suitable for a professional security investigation report. If all IP related data is missing, state 'Information unavailable' or 'Data missing' in this section.
        2.  **Process Research:**
            * If a single process name is provided, research and generate a concise paragraph (maximum of 4 lines) explaining what this process is and its primary use, based on official vendor documentation.
            * If multiple process names are provided (as an array), research and generate a concise paragraph (maximum of 4 lines) based on the provided file hash, explaining what this file is and its primary use, based on reputable cybersecurity databases, official vendor documentation, and industry-standard technical resources.
            * If sources conflict, prioritize information from official vendor documentation or widely accepted cybersecurity databases. Maintain a professional, conversational tone, as if explaining these details to a colleague. Avoid overly technical jargon unless absolutely necessary, and explain any technical terms used. **Focus solely on reporting the research findings. Do not infer or theorize the nature of the file based on its name or research findings. Do not suggest any remediation steps, future actions, or methods for obtaining further information.** If data for a section is missing, state 'Information unavailable' or 'Data missing' in that section.
        Process Name: {fName}
        IP data {ip}
        ''',
    )
    return response.text

#This pipes all API enriched data and leverages google Gemini API
def google_api_hash(process,signers,ip, FtypeData, sig, ratio):
    client = genai.Client(api_key="")
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=f'''
You are an advanced reporting writing AI designed to generate professional reports for security investigations based on provided input.

Your task involves four main components:

1.  **IP Information Formatting:** You will receive a set of IP information. Format this data accurately and consistently. **Include only fields that contain data.** Use bullet points or tables where appropriate. Ensure the formatting is clear, organized, and suitable for a professional security investigation report. If all IP related data is missing, state 'Information unavailable' or 'Data missing' in this section.
2.  **Process Research:**
    * If a single process name is provided, research and generate a concise paragraph (maximum of 4 lines) explaining what this process is and its primary use, based on official vendor documentation.
    * If multiple process names are provided (as an array), research and generate a concise paragraph (maximum of 4 lines) based on the provided file hash, explaining what this file is and its primary use, based on reputable cybersecurity databases, official vendor documentation, and industry-standard technical resources.
    * If sources conflict, prioritize information from official vendor documentation or widely accepted cybersecurity databases. Maintain a professional, conversational tone, as if explaining these details to a colleague. Avoid overly technical jargon unless absolutely necessary, and explain any technical terms used. **Focus solely on reporting the research findings. Do not infer or theorize the nature of the file based on its name or research findings. Do not suggest any remediation steps, future actions, or methods for obtaining further information.** If data for a section is missing, state 'Information unavailable' or 'Data missing' in that section.
3.  **Process Formatting:**
    * If a single process name is provided, format the process description from step 2 using the following format for the heading: Process: {process} - {sig} - {ratio}. Do not repeat {sig} or {ratio} in the description.
    * If multiple process names are provided, list the process names in a professional manner, followed by the sig and ratio, and then the paragraph from step 2.
4.  **Singer Description:** You will also be provided with the name of a company associated with the aforementioned process. Create a brief description (maximum of 4 lines) detailing what this company does and the types of software they publish. Again, keep the language professional and digestible. Ensure that the information provided in each section is unique and does not repeat information from other sections. If data for a section is missing, state 'Information unavailable' or 'Data missing' in that section.

Your output must be coherent, well-structured, and suitable for inclusion in a formal security investigation report. Prioritize clarity and professionalism in all descriptions.

IP data: {ip}
Process: {process}
Process type: {FtypeData}
Signers: {signers}
sig: {sig}
ratio: {ratio}
fileHash: {sig}
        ''',
    )
    return response.text

