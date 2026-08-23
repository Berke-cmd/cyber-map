from src.core.neo4j_client import Neo4jClient
from typing import List, Dict, Any

class GraphBuilder:
    def __init__(self, db: Neo4jClient):
        self.db = db

    def clear_database(self):
        self.db.query("MATCH (n) DETACH DELETE n")

    def ingest_full_surface(self, root_domain: str, recon_results: List[Dict[str, Any]], mx_records: List[str]):
        self.db.query(
            "MERGE (d:Domain {name: $domain})",
            {"domain": root_domain}
        )

        for mx in mx_records:
            self.db.query("""
                MERGE (m:MailServer {name: $mx})
                WITH m
                MATCH (d:Domain {name: $domain})
                MERGE (d)-[:USES_MAILSERVER]->(m)
            """, {"domain": root_domain, "mx": mx})

        for record in recon_results:
            subdomain = record.get("subdomain")
            ips = record.get("ips", [])
            intel = record.get("intel", {})

            self.db.query("""
                MATCH (d:Domain {name: $domain})
                MERGE (s:Subdomain {name: $subdomain})
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """, {"domain": root_domain, "subdomain": subdomain})

            for ip in ips:
                self.db.query("""
                    MATCH (s:Subdomain {name: $subdomain})
                    MERGE (i:IPAddress {ip: $ip})
                    ON CREATE SET i.org = $org, i.os = $os
                    ON MATCH SET i.org = $org, i.os = $os
                    MERGE (s)-[:RESOLVES_TO]->(i)
                """, {
                    "subdomain": subdomain,
                    "ip": ip,
                    "org": intel.get("org", "Unknown"),
                    "os": intel.get("os", "Unknown")
                })

                for svc in intel.get("services", []):
                    port_num = svc.get("port")
                    product = svc.get("product", "Unknown")
                    version = svc.get("version", "")
                    
                    self.db.query("""
                        MATCH (i:IPAddress {ip: $ip})
                        MERGE (p:Port {number: $port, protocol: $protocol})
                        MERGE (i)-[:EXPOSES_PORT]->(p)
                        MERGE (srv:Service {name: $product, version: $version})
                        MERGE (p)-[:RUNS_SERVICE]->(srv)
                    """, {
                        "ip": ip,
                        "port": port_num,
                        "protocol": svc.get("transport", "tcp"),
                        "product": product,
                        "version": version
                    })

                for cve in intel.get("vulns", []):
                    self.db.query("""
                        MATCH (i:IPAddress {ip: $ip})
                        MERGE (v:Vulnerability {cve_id: $cve})
                        MERGE (i)-[:VULNERABLE_TO]->(v)
                    """, {"ip": ip, "cve": cve})
