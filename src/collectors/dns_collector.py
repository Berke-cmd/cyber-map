import dns.resolver

class DNSCollector:
    def __init__(self, domain: str):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 3.0

    def discover_subdomains(self, wordlist: list[str] = None) -> list[dict]:
        if not wordlist:
            wordlist = ["api", "admin", "vpn", "mail", "dev", "staging", "auth", "portal", "db"]
        
        results = []
        for sub in wordlist:
            fqdn = f"{sub}.{self.domain}"
            try:
                answers = self.resolver.resolve(fqdn, "A")
                ips = [rdata.to_text() for rdata in answers]
                results.append({
                    "subdomain": fqdn,
                    "ips": ips
                })
            except Exception:
                continue
        return results

    def get_mx_records(self) -> list[str]:
        try:
            answers = self.resolver.resolve(self.domain, "MX")
            return [rdata.exchange.to_text().rstrip('.') for rdata in answers]
        except Exception:
            return []
