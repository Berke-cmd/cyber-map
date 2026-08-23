import requests
import json
from typing import Set

class CrtShCollector:
    BASE_URL = "https://crt.sh/[span_0](start_span)"[span_0](end_span)

    def _init_(self, timeout: int = 15):
        self.timeout = timeout[span_1](start_span)[span_1](end_span)
        self.session = requests.Session()[span_2](start_span)[span_2](end_span)
        self.session.headers.update({
            "User-Agent": "SpecterGraph-EASM-Engine/1.0",
            "Accept": "application/json"
        })[span_3](start_span)[span_3](end_span)

    def discover_subdomains(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()[span_4](start_span)[span_4](end_span)
        params = {
            "q": f"%.{domain}",
            "output": "json"
        }[span_5](start_span)[span_5](end_span)
        
        try:
            response = self.session.get(self.BASE_URL, params=params, timeout=self.timeout)[span_6](start_span)[span_6](end_span)
            if response.status_code == 200 and response.text.strip():[span_7](start_span)[span_7](end_span)
                try:
                    data = response.json()[span_8](start_span)[span_8](end_span)
                    for entry in data:[span_9](start_span)[span_9](end_span)
                        name_value = entry.get("name_value", "")[span_10](start_span)[span_10](end_span)
                        names = name_value.split("\n")[span_11](start_span)[span_11](end_span)
                        for name in names:[span_12](start_span)[span_12](end_span)
                            name = name.strip().lower()[span_13](start_span)[span_13](end_span)
                            if name.startswith("*."):[span_14](start_span)[span_14](end_span)
                                name = name[2:][span_15](start_span)[span_15](end_span)
                            if name.endswith(domain) and name != domain:[span_16](start_span)[span_16](end_span)
                                subdomains.add(name)[span_17](start_span)[span_17](end_span)
                except json.JSONDecodeError:[span_18](start_span)[span_18](end_span)
                    pass[span_19](start_span)[span_19](end_span)
        except requests.RequestException:[span_20](start_span)[span_20](end_span)
            pass[span_21](start_span)[span_21](end_span)
            
        return subdomains[span_22](start_span)[span_22](end_span)
