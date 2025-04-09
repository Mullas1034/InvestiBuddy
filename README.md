# Investibuddy

**Investibuddy** is a GUI-based threat intelligence triage assistant designed to streamline report writing for SOC (Security Operations Center) analysts. By accepting simple inputs such as IP addresses, process names, or process hash signatures, Investibuddy enriches this data using public APIs and formats the results using Google's Gemini API—making it easier to generate clean, professional reports for security incidents.

---

## 🚀 Features

- Accepts input like:
  - IP addresses
  - Process names
  - Process hash signatures
- Enriches data using public intelligence sources
- Utilizes Gemini (free API) to auto-generate a structured, analyst-ready report
- Simple, Tkinter-powered GUI
- Ideal for SOC analysts and security professionals handling triage work

---

## 🖥️ How to Use

1. **Clone the repo**
   ```bash
   git clone https://github.com/Mullas1034/InvestiBuddy.git

---

## 💼 Example Use Case
A SOC analyst receives a suspicious IP address or process name. Instead of manually researching and formatting a report, they enter the data into Investibuddy. The tool enriches the data and outputs a polished report, ready to be pasted into an incident response document or SIEM notes.

---

## 📦 Requirements
Python 3.x \n
requests /n
google-genai

---

⚠️ Note: You must configure your Gemini API key inside the code to enable report generation. https://ai.google.dev/gemini-api/docs?_gl=1*18iymam*_up*MQ..*_ga*MTE4NTc5NjQzMS4xNzQ0MTY1MzMz*_ga_P1DBVKWT6V*MTc0NDE2NTMzMy4xLjAuMTc0NDE2NTMzMy4wLjAuMTgyMzA1NTg2Nw..
⚠️ Note: You must configure your AbuseIPDB API key inside Enrichment_Library.py to enable IP data triage. https://docs.abuseipdb.com/#introduction
⚠️ Note: You must configure your VirusTotal API key inside Enrichment_Library.py to enable Process data triage. https://www.virustotal.com/gui/sign-in

