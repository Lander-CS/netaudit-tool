import socket
import threading
import ipaddress
from typing import List
from datetime import datetime

from .config import logger, RISK_MATRIX
from .models import AuditLog

class PortScanner:
    """Módulo de varredura de portas com multi-threading eficiente."""

    def __init__(self, timeout: int = 2):
        self.timeout = timeout
        self.threads: List[threading.Thread] = []
        self.results: List[AuditLog] = []

    def scan_range(self, target: str) -> List[AuditLog]:
        """Varre um intervalo CIDR ou IP único."""
        try:
            ip_list = []
            # Identifica se é CIDR, IP único ou Hostname
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            else:
                # Tenta resolver hostname ou usa IP direto
                try:
                    ip_list = [socket.gethostbyname(target)]
                except socket.gaierror:
                     # Se falhar resolução, assume que é IP direto
                    ip_list = [target]

            logger.info(f"Iniciando varredura para: {ip_list[:3]}... (total: {len(ip_list)} hosts)")

            # Inicia threads para cada porta (concorrente)
            for ip in ip_list:
                # Varrendo portas comuns e críticas (1 a 1024 + específicas da matriz de risco)
                common_ports = list(range(1, 1025))
                risk_ports = [p for p in RISK_MATRIX.keys() if p > 1024]
                target_ports = set(common_ports + risk_ports)

                for port in target_ports:
                    thread = threading.Thread(
                        target=self._scan_single,
                        args=(ip, port),
                        daemon=True
                    )
                    thread.start()
                    self.threads.append(thread)
                    
                    # Limita threads simultâneas para evitar DDoS e crash local
                    if len(self.threads) > 50:
                        self._cleanup_threads(50)

            # Aguarda conclusão
            for thread in self.threads:
                thread.join()

            return self.results

        except Exception as e:
            logger.error(f"Erro na varredura {target}: {e}")
            return self.results

    def _cleanup_threads(self, limit: int):
        while len(self.threads) > limit:
            self.threads = [t for t in self.threads if t.is_alive()]

    def _scan_single(self, ip: str, port: int) -> None:
        """Varre um único endpoint IP:PORT."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.close()

            # Identifica serviço via banner grab
            service = self._grab_service(ip, port)
            risk_data = RISK_MATRIX.get(port, {})

            # Categoriza risco
            risk_level = risk_data.get("risk", "BAIXO")
            
            log_entry = AuditLog(
                timestamp=datetime.utcnow().isoformat(),
                host=ip,
                port=port,
                status="OPEN",
                service=service,
                risk_level=risk_level,
                details=f"Porta {port} aberta - Serviço: {service} - Risco: {risk_level}"
            )
            self.results.append(log_entry)

            logger.info(f"Porta {port} [{service}] em {ip} - Risco: {risk_level}")

        except (ConnectionRefusedError, socket.timeout):
            pass 
        except Exception as e:
            logger.debug(f"Erro varrendo {ip}:{port} - {e}")

    def _grab_service(self, ip: str, port: int) -> str:
        """Identifica o serviço baseado na porta e banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Tenta ler o banner inicial (ex: SSH, FTP, SMTP falam primeiro)
            try:
                response = sock.recv(1024)
            except socket.timeout:
                response = b""
            
            # Se não houve resposta inicial, pode ser HTTP ou serviço silencioso
            if not response:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                try:
                    response = sock.recv(1024)
                except socket.timeout:
                    pass

            sock.close()
            
            if not response:
                return RISK_MATRIX.get(port, {}).get("service", "Desconhecido")
                
            banner = response.decode('utf-8', errors='ignore').strip()
            # Limpa caracteres de controle comuns
            return banner.split('\r')[0].split('\n')[0][:60]
            
        except Exception:
            return RISK_MATRIX.get(port, {}).get("service", "Desconhecido")