import requests
from typing import Dict, Any, List
from src.core.config import Config

class ShodanIntelCollector:
    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or Config.SHODAN_API_KEY
        self.session = requests.Session()

    def get_host_intel(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return self._fallback_simulated_intel(ip)

        endpoint = f"{self.BASE_URL}/shodan/host/{ip}"
        params = {"key": self.api_key, "minify": "true"}

        try:
            response = self.session.get(endpoint, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                ports = data.get("ports", [])
                vulns = list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", [])
                org = data.get("org", "Unknown")
                os_info = data.get("os", "Unknown")
                hostnames = data.get("hostnames", [])
                
                services: List[Dict[str, Any]] = []
                for item in data.get("data", []):
                    services.append({
                        "port": item.get("port"),
                        "transport": item.get("transport", "tcp"),
                        "product": item.get("product", "Unknown"),
                        "version": item.get("version", ""),
                        "cpe": item.get("cpe", [])
                    })

                return {
                    "status": "success",
                    "ip": ip,
                    "org": org,
                    "os": os_info,
                    "ports": ports,
                    "vulns": vulns,
                    "services": services,
                    "hostnames": hostnames
                }
            elif response.status_code == 404:
                return {
                    "status": "not_found",
                    "ip": ip,
                    "org": "Unknown",
                    "os": "Unknown",
                    "ports": [],
                    "vulns": [],
                    "services": []
                }
        except requests.RequestException:
            pass

        return self._fallback_simulated_intel(ip)

    def _fallback_simulated_intel(self, ip: str) -> Dict[str, Any]:
        last_octet = int(ip.split(".")[-1]) if ip.replace(".", "").isdigit() else 1
        is_risky = (last_octet % 2 == 1)
        
        return {
            "status": "simulated",
            "ip": ip,
            "org": "Cloudflare / AWS Edge" if not is_risky else "Legacy Hosting Infrastructure",
            "os": "Linux 5.x" if not is_risky else "Ubuntu 18.04 / Apache",
            "ports": [80, 443] if not is_risky else [80, 443, 8080, 22, 3306],
            "vulns": [] if not is_risky else ["CVE-2023-38606", "CVE-2021-44228"],
            "services": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.24.0"},
                {"port": 443, "transport": "tcp", "product": "OpenSSL", "version": "1.1.1"}
            ] if not is_risky else [
                {"port": 8080, "transport": "tcp", "product": "Apache Tomcat", "version": "8.5.5"},
                {"port": 3306, "transport": "tcp", "product": "MySQL", "version": "5.7.33"}
            ]
        }
