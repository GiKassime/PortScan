# PortScan em Python com Scapy

Um scanner de portas desenvolvido em Python utilizando a biblioteca Scapy.

## 📋 Pré-requisitos

Para executar este projeto, você precisará de:

1.  **Python 3.x** instalado.
2.  **Privilégios de Administrador/Root** (o Scapy precisa disso para criar pacotes).

### Dependências de Sistema

* **Windows:** É necessário instalar o [Npcap](https://npcap.com/#download).
    * *Importante:* Durante a instalação, marque a opção "Install Npcap in WinPcap API-compatible Mode".
* **Linux:** Geralmente já vem pronto, mas pode necessitar do tcpdump (`sudo apt install tcpdump`).

### Instalação da Biblioteca
## Crie uma venv
Execute o comando abaixo para instalar a dependência do Python:

# PortScan em Python com Scapy

Um scanner de portas desenvolvido em Python utilizando a biblioteca Scapy.

## Usando um ambiente virtual (venv) e instalando Scapy

Recomendo fortemente criar um ambiente virtual para este projeto — isso evita conflitos com pacotes do sistema e resolve a mensagem "externally-managed-environment" em distribuições como Debian/Ubuntu.

1. Crie o venv (no diretório do projeto):

```bash
python3 -m venv .venv
```

2. Ative o venv:

```bash
source .venv/bin/activate
```


3. Instale as dependências do projeto (ex.: Scapy):

```bash
pip install scapy
```

Notas importantes:

- O Scapy precisa de privilégios de root para enviar pacotes raw (ex.: SYN/UDP). Para executar o scanner você pode usar sudo ao chamar o Python:

```bash
sudo python3 portscan.py <IP> [-udp|-ack|-decoy]
```

- No Linux, algumas funcionalidades do Scapy dependem de libs de sistema (geralmente já instaladas). Se o sistema reclamar, instale pacotes extras via apt (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install python3-full tcpdump libpcap-dev
```

- Se você receber a mensagem sobre "externally-managed-environment" ao tentar instalar globalmente, não passe `--break-system-packages` — crie um venv como mostrado acima.

### Como executar o `portscan.py` (exemplo):

```bash
# com venv ativado
python portscan.py 1.2.3.4 -udp

# ou como root (se necessário para envio de pacotes raw)
sudo python portscan.py 1.2.3.4 -udp
```

Como sair do venv:

```bash
deactivate
```

Remoção do venv (se necessário):

```bash
rm -rf .venv
```
