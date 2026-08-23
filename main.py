import sys
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.core.neo4j_client import Neo4jClient
from src.collectors.dns_collector import DNSCollector
from src.collectors.crtsh_collector import CrtShCollector
from src.collectors.shodan_collector import ShodanIntelCollector
from src.analytics.graph_builder import GraphBuilder
from src.ai.attack_path_analyzer import AttackPathAnalyzer

console = Console()

def resolve_subdomain(subdomain: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    try:
        answers = resolver.resolve(subdomain, "A")
        return [rdata.to_text() for rdata in answers]
    except Exception:
        return []

def run_spectergraph(target_domain: str):
    console.print(Panel.fit(
        f"[bold cyan]SpecterGraph[/bold cyan]\nHedef: [bold yellow]{target_domain}[/bold yellow]",
        border_style="cyan"
    ))

    db = None
    neo4j_active = False
    try:
        db = Neo4jClient()
        builder = GraphBuilder(db)
        builder.clear_database()
        neo4j_active = True
    except Exception:
        neo4j_active = False

    all_subdomains = set()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        crt_task = progress.add_task("crt.sh taranıyor...", total=None)
        crt_collector = CrtShCollector()
        crt_subs = crt_collector.discover_subdomains(target_domain)
        all_subdomains.update(crt_subs)
        progress.remove_task(crt_task)

        dns_task = progress.add_task("DNS taranıyor...", total=None)
        dns_collector = DNSCollector(target_domain)
        dns_subs_raw = dns_collector.discover_subdomains()
        for item in dns_subs_raw:
            all_subdomains.add(item["subdomain"])
        mx_records = dns_collector.get_mx_records()
        progress.remove_task(dns_task)

    shodan_collector = ShodanIntelCollector()
    recon_pipeline_data = []

    table = Table(title="Saldırı Yüzeyi Özeti")
    table.add_column("Subdomain", style="cyan")
    table.add_column("IP", style="magenta")
    table.add_column("Portlar", style="yellow")
    table.add_column("CVE", style="red")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        shodan_task = progress.add_task("Shodan istihbaratı alınıyor...", total=len(all_subdomains) if all_subdomains else 1)
        
        for sub in sorted(all_subdomains):
            ips = resolve_subdomain(sub)
            intel = {}
            if ips:
                intel = shodan_collector.get_host_intel(ips[0])
            
            recon_pipeline_data.append({
                "subdomain": sub,
                "ips": ips,
                "intel": intel
            })

            ports_str = ", ".join(str(p) for p in intel.get("ports", [])) if intel.get("ports") else "N/A"
            vulns_str = ", ".join(intel.get("vulns", [])) if intel.get("vulns") else "None"
            table.add_row(sub, ", ".join(ips) if ips else "Unresolved", ports_str, vulns_str)
            progress.advance(shodan_task)

    console.print(table)

    if neo4j_active and db:
        builder.ingest_full_surface(target_domain, recon_pipeline_data, mx_records)
        analyzer = AttackPathAnalyzer(db)
        report = analyzer.analyze_risk_and_attack_paths(target_domain)
        console.print("\n" + "="*80)
        console.print(Panel(report, title="Rapor", border_style="red"))
        console.print("="*80 + "\n")
        db.close()
    else:
        console.print("[yellow][!] Neo4j aktif değil, OSINT yüzey tarama sonuçları yukarıda listelendi.[/yellow]")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    run_spectergraph(target)
