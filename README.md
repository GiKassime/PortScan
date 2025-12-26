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

Execute o comando abaixo para instalar a dependência do Python:

```bash
pip install scapy