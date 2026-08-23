from openai import OpenAI
from src.core.config import Config
from src.core.neo4j_client import Neo4jClient

class AttackPathAnalyzer:
    def _init_(self, db: Neo4jClient):
        self.db = db
        self.client = OpenAI(api_key=Config.OPENAI_API_KEY) if Config.OPENAI_API_KEY else None

    def export_graph_topology(self) -> str:
        query = """
        MATCH (s:Subdomain)-[:RESOLVES_TO]->(i:IPAddress)
        OPTIONAL MATCH (i)-[:EXPOSES_PORT]->(p:Port)-[:RUNS_SERVICE]->(srv:Service)
        OPTIONAL MATCH (i)-[:VULNERABLE_TO]->(v:Vulnerability)
        RETURN s.name AS subdomain, i.ip AS ip, collect(DISTINCT p.number) AS ports, collect(DISTINCT srv.name) AS services, collect(DISTINCT v.cve_id) AS vulns
        """
        records = self.db.query(query)
        topology_summary = []
        for r in records:
            topology_summary.append(
                f"- Subdomain: {r['subdomain']} | IP: {r['ip']} | Ports: {r['ports']} | Services: {r['services']} | CVEs: {r['vulns']}"
            )
        return "\n".join(topology_summary)

    def analyze_risk_and_attack_paths(self, domain: str) -> str:
        topology = self.export_graph_topology()
        
        if not self.client:
            return f"Topoloji:\n{topology}"

        prompt = f"""
        Hedef: {domain}
        Topoloji:
        {topology}

        1. Saldırı rotasını listele.
        2. En riskli bileşeni belirt.
        3. MITRE ATT&CK eşleştirmelerini ver.
        4. Blue team önlemlerini belirt.
        """

        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Siber güvenlik uzmanı olarak analiz yap."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return response.choices[0].message.content
