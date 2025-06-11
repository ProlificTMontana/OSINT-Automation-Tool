# OSINT Automation Tool

## Overview

The OSINT Automation Tool is a Python application that gathers open-source intelligence (OSINT) using various plugins. It supports querying information from APIs like Shodan and HaveIBeenPwned, as well as scraping data from popular social media platforms.

## Features

- **Shodan API**: Retrieve information about IP addresses and domains.
- **HaveIBeenPwned API**: Check if an email or domain has been involved in data breaches.
- **Web Scraping**: Check for username availability on platforms like GitHub, Twitter, Instagram, Facebook, LinkedIn, and Reddit.


## Installation

1. Clone the repository:
```bash
   git clone https://github.com/ProlificTMontana/OSINT-Automation-Tool.git
   cd OSINT-Automation-Tool
```
   
2. Install the required packages:
```bash
pip install -r requirements.txt
```

##Usage

1. Run the application:
```bash
python -m streamlit run main.py
```
2. Open your web browser and navigate to http://localhost:8501.

3. Enter a username, domain, or IP address to gather OSINT information.

##API Keys

- Shodan API: You will need a valid API key to use the Shodan plugin. You can obtain one by signing up at Shodan.

#Exporting Results

The tool allows you to export the gathered results in JSON or CSV format.
