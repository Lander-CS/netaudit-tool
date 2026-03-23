from collections import defaultdict
from typing import List, Dict
from datetime import datetime
from .models import AuditLog

def analyze_results(results: List[AuditLog]) -> Dict:
    """Análise de resultados e geração de relatórios."""
    if not results:
        return {"error": "Nenhum resultado encontrado"}

    hosts_vulnerabilities = defaultdict(list)
    total_open_ports = 0
    risk_counts = {"CRÍTICO": 0, "ALTO": 0, "MÉDIO": 0}

    for result in results:
        hosts_vulnerabilities[result.host].append(result.to_dict())
        total_open_ports += 1
        if result.risk_level in risk_counts:
            risk_counts[result.risk_level] += 1

    # Gera ranking de hosts por criticidade
    host_ranking = []
    for host, vulns in hosts_vulnerabilities.items():
        # Recalcula vulns como objetos ou dicts
        crit = sum(1 for v in vulns if v['risk_level'] == "CRÍTICO")
        high = sum(1 for v in vulns if v['risk_level'] == "ALTO")
        med = sum(1 for v in vulns if v['risk_level'] == "MÉDIO")
        
        risk_score = (crit * 10) + (high * 5) + (med * 1)
        
        host_ranking.append({
            "host": host,
            "vulnerabilities": len(vulns),
            "risk_score": risk_score,
            "risk_level": get_overall_risk(risk_score)
        })

    host_ranking.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "audit_summary": {
            "timestamp": datetime.utcnow().isoformat(),
            "total_hosts": len(hosts_vulnerabilities),
            "total_open_ports": total_open_ports,
            "critical_risks": risk_counts["CRÍTICO"],
            "high_risks": risk_counts["ALTO"],
            "medium_risks": risk_counts["MÉDIO"],
            "total_risk_score": (risk_counts["CRÍTICO"] * 10) + (risk_counts["ALTO"] * 5) + (risk_counts["MÉDIO"] * 2)
        },
        "top_vulnerable_hosts": host_ranking[:10],
        "host_details": dict(hosts_vulnerabilities),
        "recommendations": generate_recommendations(results)
    }

def get_overall_risk(score: int) -> str:
    if score >= 30: return "CRÍTICO"
    elif score >= 15: return "ALTO"
    elif score >= 5: return "MÉDIO"
    else: return "BAIXO"

def generate_recommendations(results: List[AuditLog]) -> List[Dict]:
    recommendations = []
    service_risks = defaultdict(int)
    service_ports = {}

    for result in results:
        service_risks[result.service] += 1
        service_ports[result.service] = result.port

    for service, count in service_risks.items():
        recommendations.append({
            "service": service,
            "count": count,
            "recommendation": f"Revise o serviço {service} (Porta {service_ports.get(service)}). Considere firewall ou atualização."
        })
    return recommendations

def display_dashboard(results: List[AuditLog]) -> None:
    """Exibe dashboard de segurança de rede."""
    print("\n" + "="*80)
    print("🔒 NETWORK SECURITY AUDIT DASHBOARD")
    print("="*80)
    
    if not results:
        print("Nenhuma vulnerabilidade ou porta aberta encontrada.")
        return

    print(f" Total de portas abertas encontradas: {len(results)}")
    
    hosts = set(r.host for r in results)
    print(f" Hosts afetados: {len(hosts)}")

    # Contagem de riscos
    c = sum(1 for r in results if r.risk_level == "CRÍTICO")
    h = sum(1 for r in results if r.risk_level == "ALTO")
    m = sum(1 for r in results if r.risk_level == "MÉDIO")

    print(f"🔴 Críticos: {c} | 🟠 Altos: {h} | 🟡 Médios: {m}")
    print("-" * 40)

    # Listagem simplificada
    processed_hosts = set()
    for r in results:
        if r.host not in processed_hosts:
            print(f"\n🖥️  Host: {r.host}")
            processed_hosts.add(r.host)
        print(f"   └─ :{r.port:<5} ({r.service}) -> {r.risk_level}")
    print("\n" + "="*80)