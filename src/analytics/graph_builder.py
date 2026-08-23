from src.core.neo4j_client import Neo4jClient
from typing import List, Dict, Any

class GraphBuilder:
    def _init_(self, db: Neo4jClient):
        self.db = db[span_50](start_span)[span_50](end_span)

    def clear_database(self):
        self.db.query("MATCH (n) DETACH DELETE n")[span_51](start_span)[span_51](end_span)

    def ingest_full_surface(self, root_domain: str, recon_results: List[Dict[str, Any]], mx_records: List[str]):
        self.db.query(
            "MERGE (d:Domain {name: $domain})",
            {"domain": root_domain}
        )[span_52](start_span)[span_52](end_span)

        for mx in mx_records:[span_53](start_span)[span_53](end_span)
            self.db.query("""
                MERGE (m:MailServer {name: $mx})
                WITH m
                MATCH (d:Domain {name: $domain})
                MERGE (d)-[:USES_MAILSERVER]->(m)
            """, {"domain": root_domain, "mx": mx})[span_54](start_span)[span_54](end_span)

        for record in recon_results:[span_55](start_span)[span_55](end_span)
            subdomain = record.get("subdomain")[span_56](start_span)[span_56](end_span)
            ips = record.get("ips", [])[span_57](start_span)[span_57](end_span)
            intel = record.get("intel", {})[span_58](start_span)[span_58](end_span)

            self.db.query("""
                MATCH (d:Domain {name: $domain})
                MERGE (s:Subdomain {name: $subdomain})
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """, {"domain": root_domain, "subdomain": subdomain})[span_59](start_span)[span_59](end_span)

            for ip in ips:[span_60](start_span)[span_60](end_span)
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
                })[span_61](start_span)[span_61](end_span)

                for svc in intel.get("services", []):[span_62](start_span)[span_62](end_span)
                    port_num = svc.get("port")[span_63](start_span)[span_63](end_span)
                    product = svc.get("product", "Unknown")[span_64](start_span)[span_64](end_span)
                    version = svc.get("version", "")[span_65](start_span)[span_65](end_span)
                    
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
                    })[span_66](start_span)[span_66](end_span)

                for cve in intel.get("vulns", []):[span_67](start_span)[span_67](end_span)
                    self.db.query("""
                        MATCH (i:IPAddress {ip: $ip})
                        MERGE (v:Vulnerability {cve_id: $cve})
                        MERGE (i)-[:VULNERABLE_TO]->(v)
                    """, {"ip": ip, "cve": cve})[span_68](start_span)[span_68](end_span)
