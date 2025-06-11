import streamlit as st
import requests
import json
import csv
import io
from abc import ABC, abstractmethod
from bs4 import BeautifulSoup

# Plugin Interface
class OSINTPlugin(ABC):
    @abstractmethod
    def requires_input_type(self):
        """Return supported input types: 'username', 'domain', 'ip'"""
        pass

    @abstractmethod
    def run(self, target):
        """Run plugin on target and return results dictionary"""
        pass

# Plugin: Shodan API
class ShodanPlugin(OSINTPlugin):
    def __init__(self, api_key):
        self.api_key = api_key

    def requires_input_type(self):
        return ['ip', 'domain']

    def run(self, target):
        url = ''
        results = {}
        headers = {'Accept': 'application/json'}
        try:
            if self._is_ip(target):
                url = f'https://api.shodan.io/shodan/host/{target}?key={self.api_key}'
                resp = requests.get(url, headers=headers)
                if resp.status_code == 200:
                    results = resp.json()
                else:
                    results['error'] = f'Shodan API error: {resp.status_code} {resp.text}'
            else:
                # Shodan domain search (via query)
                url = f'https://api.shodan.io/shodan/host/search?key={self.api_key}&query=hostname:"{target}"'
                resp = requests.get(url, headers=headers)
                if resp.status_code == 200:
                    results = resp.json()
                else:
                    results['error'] = f'Shodan API error: {resp.status_code} {resp.text}'
        except Exception as e:
            results['error'] = str(e)
        return {'shodan': results}

    def _is_ip(self, input_str):
        parts = input_str.split('.')
        if len(parts) != 4:
            return False
        for item in parts:
            if not item.isdigit():
                return False
            i = int(item)
            if i < 0 or i > 255:
                return False
        return True

# Plugin: HaveIBeenPwned API
class HIBPPlugin(OSINTPlugin):
    def __init__(self):
        pass

    def requires_input_type(self):
        return ['username', 'domain', 'ip']

    def run(self, target):
        results = {}
        # Try to detect if target looks like email, domain or username
        # The HIBP API supports email & domain breaches and pastes, but 
        # does not support ip directly; fallback to check if it's an email or domain for lookup
        headers = {'User-Agent': 'OSINT-Automation-Tool'}
        try:
            # Email address breach check
            if '@' in target:
                url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{target}'
                resp = requests.get(url, headers=headers)
                if resp.status_code == 200:
                    results['breaches'] = resp.json()
                elif resp.status_code == 404:
                    results['breaches'] = []
                else:
                    results['error'] = f'HIBP API error: {resp.status_code} {resp.text}'
            # Domain breach check
            elif '.' in target:
                url = f'https://haveibeenpwned.com/api/v3/breaches?domain={target}'
                resp = requests.get(url, headers=headers)
                if resp.status_code == 200:
                    results['breaches'] = resp.json()
                else:
                    results['error'] = f'HIBP API error: {resp.status_code} {resp.text}'
            else:
                # Username: no direct API support, search breach by username is not supported directly,
                # so returning something generic or empty.
                results['message'] = 'HIBP API does not support username search directly'
        except Exception as e:
            results['error'] = str(e)
        return {'hibp': results}

# Plugin: Generic Web Scraping for username on example sites
class WebScrapePlugin(OSINTPlugin):
    def __init__(self):
        # Sites can be extended with more URLs or scraping logic
        self.sites = [
            {
                'name': 'GitHub',
                'url_template': 'https://github.com/{}',
                'check_username': True
            },
            {
                'name': 'Twitter',
                'url_template': 'https://twitter.com/{}',
                'check_username': True
            },
            {
                'name': 'Instagram',
                'url_template': 'https://www.instagram.com/{}/',
                'check_username': True
            },
            {
                'name': 'Facebook',
                'url_template': 'https://www.facebook.com/{}',
                'check_username': True
            },
            {
                'name': 'LinkedIn',
                'url_template': 'https://www.linkedin.com/in/{}',
                'check_username': True
            },
            {
                'name': 'Reddit',
                'url_template': 'https://www.reddit.com/user/{}',
                'check_username': True
            }
        ]


    def requires_input_type(self):
        return ['username']

    def run(self, target):
        results = {}
        for site in self.sites:
            url = site['url_template'].format(target)
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    # Assuming user exists if profile page loads
                    results[site['name']] = {'exists': True, 'profile_url': url}
                elif resp.status_code == 404:
                    results[site['name']] = {'exists': False, 'profile_url': url}
                else:
                    results[site['name']] = {'error': f'HTTP {resp.status_code}'}
            except Exception as e:
                results[site['name']] = {'error': str(e)}
        return {'webscrape': results}

# Main OSINT Automation Controller
class OSINTAutomation:
    def __init__(self, shodan_api_key=None):
        self.plugins = []
        self.shodan_api_key = shodan_api_key
        self.load_plugins()

    def load_plugins(self):
        # Load all plugins
        if self.shodan_api_key:
            self.plugins.append(ShodanPlugin(self.shodan_api_key))
        self.plugins.append(HIBPPlugin())
        self.plugins.append(WebScrapePlugin())

    def supported_plugins(self, input_type):
        return [p for p in self.plugins if input_type in p.requires_input_type()]

    def run_all(self, input_type, target):
        results = {}
        for plugin in self.supported_plugins(input_type):
            plugin_result = plugin.run(target)
            results.update(plugin_result)
        return results

# Export functions
def export_to_json(data):
    return json.dumps(data, indent=4)

def export_to_csv(data):
    output = io.StringIO()
    writer = csv.writer(output)

    # CSV header guessing: flatten dictionary keys by level 2 and output rows
    # This is a simple flattening for one-level keys under plugins
    all_keys = set()
    rows = []

    # Flatten the nested dict structure: plugin -> keys.
    for plugin_name, content in data.items():
        if isinstance(content, dict):
            for key, value in content.items():
                all_keys.add(f"{plugin_name}.{key}")
        else:
            all_keys.add(plugin_name)

    all_keys = sorted(all_keys)
    writer.writerow(all_keys)

    # Collect row data for one record (target)
    row = []
    for key in all_keys:
        plugin_name, subkey = key.split('.', 1)
        val = data.get(plugin_name, {}).get(subkey, '')
        # If JSON object, convert to string
        if isinstance(val, (dict,list)):
            val = json.dumps(val)
        row.append(val)
    writer.writerow(row)
    return output.getvalue()

# Streamlit UI
def main():
    st.title("OSINT Automation Tool")

    st.markdown("""
    Enter a username, domain, or IP to gather open-source intelligence automatically using plugins:
    - Shodan (IP, Domain)
    - HaveIBeenPwned (Email, Domain)
    - Web scraping (Usernames on GitHub, Twitter, Instagram, LinkedIn, Facebook,Reddit)
    """)

    input_type = st.selectbox("Select Input Type", ['username', 'domain', 'ip'])
    target = st.text_input(f"Enter {input_type} here")

    shodan_api_key = st.text_input("Shodan API Key (for Shodan plugin)")
    if not shodan_api_key and input_type in ['ip', 'domain']:
        st.warning("Shodan plugin requires an API key for IP and Domain lookup.")

    if st.button("Run OSINT Scan"):
        if not target:
            st.error("Please enter a target to scan.")
            return

        tool = OSINTAutomation(shodan_api_key=shodan_api_key if shodan_api_key else None)
        with st.spinner("Gathering OSINT information..."):
            results = tool.run_all(input_type, target)

        st.subheader("Raw Results (JSON):")
        st.json(results)

        export_format = st.radio("Export Results as:", ['JSON', 'CSV'])
        if st.button("Export Data"):
            if export_format == 'JSON':
                output = export_to_json(results)
                st.download_button(label="Download JSON", data=output, file_name=f"osint_{target}.json", mime='application/json')
            else:
                output = export_to_csv(results)
                st.download_button(label="Download CSV", data=output, file_name=f"osint_{target}.csv", mime='text/csv')

if __name__ == "__main__":
    main()


