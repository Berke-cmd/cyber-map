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

console = Console()[span_69](start_span)[span_69](end_span)

def resolve_subdomain(subdomain: str) -> list[str]:
    resolver = dns.resolver.Resolver()[span_70](start_span)[span_70](end_span)
    resolver.timeout = 2.0[span_71](start_span)[span_71](end_span)
    resolver.lifetime = 2.0[span_72](start_span)[span_72](end_span)
    try:
        answers = resolver.resolve(subdomain, "A")[span_73](start_span)[span_73](end_span)
        return [rdata.to_text() for rdata in answers][span_74](start_span)[span_74](end_span)
    except Exception:
        return [][span_75](start_span)[span_75](end_span)

def run_spectergraph(target_domain: str):
    console.print(Panel.fit(
        f"[bold cyan]SpecterGraph[/bold cyan]\nHedef: [bold yellow]{target_domain}[/bold yellow]",
        border_style="cyan"
    ))[span_76](start_span)[span_76](end_span)

    db = Neo4jClient()[span_77](start_span)[span_77](end_span)
    builder = GraphBuilder(db)[span_78](start_span)[span_78](end_span)
    builder.clear_database()[span_79](start_span)[span_79](end_span)

    all_subdomains = set()[span_80](start_span)[span_80](end_span)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:[span_81](start_span)[span_81](end_span)
        crt_task = progress.add_task("crt.sh taranıyor...", total=None)[span_82](start_span)[span_82](end_span)
        crt_collector = CrtShCollector()[span_83](start_span)[span_83](end_span)
        crt_subs = crt_collector.discover_subdomains(target_domain)[span_84](start_span)[span_84](end_span)
        all_subdomains.update(crt_subs)[span_85](start_span)[span_85](end_span)
        progress.remove_task(crt_task)[span_86](start_span)[span_86](end_span)

        dns_task = progress.add_task("DNS taranıyor...", total=None)[span_87](start_span)[span_87](end_span)
        dns_collector = DNSCollector(target_domain)[span_88](start_span)[span_88](end_span)
        dns_subs_raw = dns_collector.discover_subdomains()[span_89](start_span)[span_89](end_span)
        for item in dns_subs_raw:[span_90](start_span)[span_90](end_span)
            all_subdomains.add(item["subdomain"])[span_91](start_span)[span_91](end_span)
        mx_records = dns_collector.get_mx_records()[span_92](start_span)[span_92](end_span)
        progress.remove_task(dns_task)[span_93](start_span)[span_93](end_span)

    shodan_collector = ShodanIntelCollector()[span_94](start_span)[span_94](end_span)
    recon_pipeline_data = [][span_95](start_span)[span_95](end_span)

    table = Table(title="Saldırı Yüzeyi Özeti")[span_96](start_span)[span_96](end_span)
    table.add_column("Subdomain", style="cyan")[span_97](start_span)[span_97](end_span)
    table.add_column("IP", style="magenta")[span_98](start_span)[span_98](end_span)
    table.add_column("Portlar", style="yellow")[span_99](start_span)[span_99](end_span)
    table.add_column("CVE", style="red")[span_100](start_span)[span_100](end_span)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:[span_101](start_span)[span_101](end_span)
        shodan_task = progress.add_task("Shodan istihbaratı alınıyor...", total=len(all_subdomains))[span_102](start_span)[span_102](end_span)
        
        for sub in sorted(all_subdomains):[span_103](start_span)[span_103](end_span)
            ips = resolve_subdomain(sub)[span_104](start_span)[span_104](end_span)
            intel = {}[span_105](start_span)[span_105](end_span)
            if ips:[span_106](start_span)[span_106](end_span)
                intel = shodan_collector.get_host_intel(ips[0])[span_107](start_span)[span_107](end_span)
            
            recon_pipeline_data.append({
                "subdomain": sub,
                "ips": ips,
                "intel": intel
            })[span_108](start_span)[span_108](end_span)

            ports_str = ", ".join(str(p) for p in intel.get("ports", [])) if intel.get("ports") else "N/A[span_109](start_span)"[span_109](end_span)
            vulns_str = ", ".join(intel.get("vulns", [])) if intel.get("vulns") else "None[span_110](start_span)"[span_110](end_span)
            table.add_row(sub, ", ".join(ips) if ips else "Unresolved", ports_str, vulns_str)[span_111](start_span)[span_111](end_span)
            progress.advance(shodan_task)[span_112](start_span)[span_112](end_span)

    console.print(table)[span_113](start_span)[span_113](end_span)

    builder.ingest_full_surface(target_domain, recon_pipeline_data, mx_records)[span_114](start_span)[span_114](end_span)

    analyzer = AttackPathAnalyzer(db)[span_115](start_span)[span_115](end_span)
    report = analyzer.analyze_risk_and_attack_paths(target_domain)[span_116](start_span)[span_116](end_span)

    console.print("\n" + "="*80)[span_117](start_span)[span_117](end_span)
    console.print(Panel(report, title="Rapor", border_style="red"))[span_118](start_span)[span_118](end_span)
    console.print("="*80 + "\n")[span_119](start_span)[span_119](end_span)

    db.close()[span_120](start_span)[span_120](end_span)

if _name_ == "_main_":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com[span_121](start_span)"[span_121](end_span)
    run_spectergraph(target)[span_122](start_span)[span_122](end_span)
