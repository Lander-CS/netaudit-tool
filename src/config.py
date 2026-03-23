import logging
import sys
import os

# =============================================================================
# CONFIGURAÇÃO DE LOGGING
# =============================================================================
def setup_logging():
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(os.path.join(reports_dir, 'network_audit.log'))
        ]
    )
    return logging.getLogger("NetworkAudit")

logger = setup_logging()

# =============================================================================
# MATRIZ DE RISCO - NIST SP 800-53
# =============================================================================
RISK_MATRIX = {
    # Risco Crítico - Portas inseguras/exploatáveis
    21: {"service": "FTP", "risk": "CRÍTICO", "severity": 10, "cve": "Múltiplos"},
    23: {"service": "Telnet", "risk": "CRÍTICO", "severity": 10, "cve": "Inseguro"},
    445: {"service": "SMB", "risk": "CRÍTICO", "severity": 9, "cve": "EternalBlue"},
    135: {"service": "MSRPC", "risk": "CRÍTICO", "severity": 9, "cve": "Ataques remotos"},
    139: {"service": "NetBIOS", "risk": "CRÍTICO", "severity": 8, "cve": "Inseguro"},
    443: {"service": "HTTPS", "risk": "MÉDIO", "severity": 4, "cve": "Depende do SSL/TLS"},
    3389: {"service": "RDP", "risk": "ALTO", "severity": 8, "cve": "BlueKeep"},
    5985: {"service": "WinRM", "risk": "ALTO", "severity": 7, "cve": "Depende"},
    5986: {"service": "WinRM-HTTPS", "risk": "ALTO", "severity": 7, "cve": "Depende"},
    8443: {"service": "HTTPS-Alt", "risk": "MÉDIO", "severity": 4, "cve": "Depende"},

    # Risco Alto - Serviços sensíveis
    25: {"service": "SMTP", "risk": "ALTO", "severity": 6, "cve": "SPF/BIMI"},
    587: {"service": "Submission", "risk": "ALTO", "severity": 6, "cve": "Relay"},
    993: {"service": "IMAPS", "risk": "MÉDIO", "severity": 5, "cve": "Credencial leakage"},
    995: {"service": "POP3S", "risk": "MÉDIO", "severity": 5, "cve": "Credencial leakage"},

    # Risco Médio - Serviços comuns
    80: {"service": "HTTP", "risk": "MÉDIO", "severity": 4, "cve": "Depende do app"},
    22: {"service": "SSH", "risk": "MÉDIO", "severity": 5, "cve": "Depende da versão"},
    2526: {"service": "VXWORKS", "risk": "CRÍTICO", "severity": 9, "cve": "Específico"},

    # Portas de gerenciamento
    161: {"service": "SNMP", "risk": "ALTO", "severity": 7, "cve": "V1/V2 inseguros"},
    162: {"service": "SNMP-Trap", "risk": "ALTO", "severity": 6, "cve": "Traps não criptografadas"},
    631: {"service": "IPP", "risk": "MÉDIO", "severity": 5, "cve": "Impressão insegura"},
    2049: {"service": "NFS", "risk": "CRÍTICO", "severity": 9, "cve": "Arquivos em rede"},
    20022: {"service": "SSH-Alt", "risk": "MÉDIO", "severity": 4, "cve": "Depende"},

    # Portas desconhecidas ou suspeitas
    31337: {"service": "ELITE Backdoor", "risk": "CRÍTICO", "severity": 10, "cve": "Porta bem-known"},
}