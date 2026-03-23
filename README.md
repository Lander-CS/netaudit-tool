# 🔐 Network Security Audit Tool (NetAudit)

Ferramenta profissional de auditoria de segurança de rede desenvolvida em Python. Realiza varredura de portas, identificação de serviços (Banner Grabbing) e análise de riscos baseada na matriz NIST SP 800-53.

## 🚀 Funcionalidades

- **Varredura Multi-thread**: Scanner de portas rápido e eficiente.
- **Identificação de Serviços**: Banner Grabbing para detectar serviços reais rodando nas portas.
- **Análise de Risco**: Classificação automática (Crítico, Alto, Médio, Baixo) baseada em normas de segurança.
- **Relatórios**: Gera relatórios em JSON detalhados e logs de auditoria na pasta `reports/`.
- **Dashboard CLI**: Resumo visual direto no terminal.

## 📋 Pré-requisitos

- Python 3.8 ou superior.
- Permissões de administrador (recomendado para varreduras de rede precisas).

## 🔧 Instalação

1. Clone o repositório e entre na pasta:
   ```bash
   cd netaudit
   ```

2. Crie um ambiente virtual (opcional, mas recomendado):
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/Mac:
   source venv/bin/activate
   ```

3. Instale a ferramenta em modo editável:
   ```bash
   pip install -e .
   ```

## 💻 Como Usar

Após a instalação, o comando `netaudit` estará disponível globalmente no seu terminal (dentro do ambiente virtual).

### Exemplos:

**1. Varrer um IP único:**
```bash
netaudit 192.168.1.15
```

**2. Varrer múltiplos alvos:**
```bash
netaudit 192.168.1.15,10.0.0.5
```

**3. Varrer uma sub-rede inteira (CIDR):**
```bash
netaudit 192.168.1.0/24
```

**4. Salvar relatório em local específico:**
```bash
netaudit 192.168.1.1 --output "C:/MeusDocumentos/auditoria_cliente_x.json"
```

## ⚠️ Aviso Legal

**ETHICAL USE ONLY:** Esta ferramenta deve ser utilizada **APENAS** em redes onde você possui autorização explícita para auditoria. O uso não autorizado pode violar leis de crimes cibernéticos (ex: Lei 12.737/13 no Brasil).