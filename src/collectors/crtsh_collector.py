import requests
import json
from typing import Set

class CrtShCollector:
    BASE_URL = "https://crt.sh/"

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SpecterGraph-EASM-Engine/1.0",
            "Accept": "application/json"
        })

    def discover_subdomains(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        params = {
            "q": f"%.{domain}",
            "output": "json"
        }
        
        try:
            response = self.session.get(self.BASE_URL, params=params, timeout=self.timeout)
            if response.status_code == 200 and response.text.strip():
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        names = name_value.split("\n")
                        for name in names:
                            name = name.strip().lower()
                            if name.startswith("*."):
                                name = name[2:]
                            if name.endswith(domain) and name != domain:
                                subdomains.add(name)
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            pass
            
        return subdomains
