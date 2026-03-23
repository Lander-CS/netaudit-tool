import json
import argparse
import sys
import os
from datetime import datetime

from .scanner import PortScanner
from .analyzer import analyze_results, display_dashboard

def main():
    """Função principal do auditor (CLI)."""
    print("\n" + "="*80)
    print(" NETWORK SECURITY AUDIT TOOL (NetAudit)")
    print("="*80)
    print("⚠️  AVISO: Use APENAS em redes autorizadas!")
    print("="*80)

    parser = argparse.ArgumentParser(description="Ferramenta Profissional de Auditoria de Segurança de Rede")
    parser.add_argument("target", help="Alvo (IP, Hostname, CIDR ou lista separada por vírgulas)")
    parser.add_argument("--output", "-o", help="Caminho do arquivo de saída JSON (opcional)")
    
    args = parser.parse_args()

    # Processa alvos
    target_list = [t.strip() for t in args.target.split(",") if t.strip()]
    
    print(f"\n Iniciando auditoria em {len(target_list)} alvos/redes...")
    print(f" Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Executa Scan
    scanner = PortScanner()
    all_results = []
    
    try:
        for t in target_list:
            print(f"   > Varrendo alvo: {t}")
            results = scanner.scan_range(t)
            all_results.extend(results)
    except KeyboardInterrupt:
        print("\n❌ Interrompido pelo usuário.")
        sys.exit(1)

    # Exibe Dashboard
    display_dashboard(all_results)

    # Gera Relatório
    report = analyze_results(all_results)

    # Define caminho de saída
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    if args.output:
        output_file = os.path.abspath(args.output)
    else:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{timestamp_str}.json"
        output_file = os.path.abspath(os.path.join(reports_dir, filename))

    # Salva JSON
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    # Caminho do Log (definido no config.py como reports/network_audit.log)
    log_file = os.path.abspath(os.path.join(reports_dir, "network_audit.log"))

    print("\n" + "="*80)
    print(" AUDITORIA CONCLUÍDA")
    print("="*80)
    print(f" Relatório JSON: {output_file}")
    print(f" Log de Auditoria: {log_file}")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
