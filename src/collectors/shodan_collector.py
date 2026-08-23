import requests
from typing import Dict, Any, List
from src.core.config import Config

class ShodanIntelCollector:
    BASE_URL = "https://api.shodan.io[span_23](start_span)"[span_23](end_span)

    def _init_(self, api_key: str = None):
        self.api_key = api_key or Config.SHODAN_API_KEY[span_24](start_span)[span_24](end_span)
        self.session = requests.Session()[span_25](start_span)[span_25](end_span)

    def get_host_intel(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:[span_26](start_span)[span_26](end_span)
            return self._fallback_simulated_intel(ip)[span_27](start_span)[span_27](end_span)

        endpoint = f"{self.BASE_URL}/shodan/host/{ip}[span_28](start_span)"[span_28](end_span)
        params = {"key": self.api_key, "minify": "true"}[span_29](start_span)[span_29](end_span)

        try:
            response = self.session.get(endpoint, params=params, timeout=10)[span_30](start_span)[span_30](end_span)
            if response.status_code == 200:[span_31](start_span)[span_31](end_span)
                data = response.json()[span_32](start_span)[span_32](end_span)
                
                ports = data.get("ports", [])[span_33](start_span)[span_33](end_span)
                vulns = list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", [])[span_34](start_span)[span_34](end_span)
                org = data.get("org", "Unknown")[span_35](start_span)[span_35](end_span)
                os_info = data.get("os", "Unknown")[span_36](start_span)[span_36](end_span)
                hostnames = data.get("hostnames", [])[span_37](start_span)[span_37](end_span)
                
                services: List[Dict[str, Any]] = [][span_38](start_span)[span_38](end_span)
                for item in data.get("data", []):[span_39](start_span)[span_39](end_span)
                    services.append({
                        "port": item.get("port"),
                        "transport": item.get("transport", "tcp"),
                        "product": item.get("product", "Unknown"),
                        "version": item.get("version", ""),
                        "cpe": item.get("cpe", [])
                    })[span_40](start_span)[span_40](end_span)

                return {
                    "status": "success",
                    "ip": ip,
                    "org": org,
                    "os": os_info,
                    "ports": ports,
                    "vulns": vulns,
                    "services": services,
                    "hostnames": hostnames
                }[span_41](start_span)[span_41](end_span)
            elif response.status_code == 404:[span_42](start_span)[span_42](end_span)
                return {
                    "status": "not_found",
                    "ip": ip,
                    "org": "Unknown",
                    "os": "Unknown",
                    "ports": [],
                    "vulns": [],
                    "services": []
                }[span_43](start_span)[span_43](end_span)
        except requests.RequestException:[span_44](start_span)[span_44](end_span)
            pass[span_45](start_span)[span_45](end_span)

        return self._fallback_simulated_intel(ip)[span_46](start_span)[span_46](end_span)

    def _fallback_simulated_intel(self, ip: str) -> Dict[str, Any]:
        last_octet = int(ip.split(".")[-1]) if ip.replace(".", "").isdigit() else 1[span_47](start_span)[span_47](end_span)
        is_risky = (last_octet % 2 == 1)[span_48](start_span)[span_48](end_span)
        
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
        }[span_49](start_span)[span_49](end_span)
