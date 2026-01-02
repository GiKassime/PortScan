# 🔍 PortScan - Scanner de Portas em Python

Scanner de portas desenvolvido com Scapy, suportando múltiplos tipos de scan (SYN, UDP, ACK, Decoy).

---

## 📋 Requisitos

- **Python 3.x**
- **Privilégios de Administrador/Root** (necessário para envio de pacotes raw)
- **Dependências de sistema:**
  - **Windows:** [Npcap](https://npcap.com/#download) (marque "WinPcap API-compatible Mode")
  - **Linux:** `sudo apt install tcpdump libpcap-dev`

---

## ⚙️ Instalação

### 1. Clone o repositório
```bash
git clone https://github.com/GiKassime/PortScan.git
cd PortScan
```

### 2. Crie um ambiente virtual (recomendado)
```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# ou
.venv\Scripts\activate     # Windows
```

### 3. Instale as dependências
```bash
pip install -r requirements.txt
```

---

## 🚀 Uso

### Menu de Ajuda
```bash
python3 portscan.py -help
```

![Menu de Ajuda](imgs/help.png)

---

## 📊 Tipos de Scan

### 1️⃣ SYN Scan (Padrão)
Técnica stealth que não completa o three-way handshake TCP.

**Comando:**
```bash
sudo python3 portscan.py <IP> -p 1-1000
```

**Resultado do Scan:**

![SYN Scan - Resultado](imgs/syn.png)

**Captura no Wireshark:**

![SYN Scan - Wireshark](imgs/syn_wireshark.png)

---

### 2️⃣ UDP Scan
Identifica portas UDP abertas (mais lento que TCP).

**Comando:**
```bash
sudo python3 portscan.py <IP> -udp -p 1-1000
```

**Resultado do Scan:**

![UDP Scan - Resultado](imgs/udp.png)

**Captura no Wireshark:**

![UDP Scan - Wireshark](imgs/udp_wireshark.png)

---

### 3️⃣ ACK Scan
Detecta regras de firewall e portas filtradas.

**Comando:**
```bash
sudo python3 portscan.py <IP> -ack -p 1-1000
```

**Resultado do Scan:**

![ACK Scan - Resultado](imgs/ack.png)

**Captura no Wireshark:**

![ACK Scan - Wireshark](imgs/ack_wireshark.png)

---

### 4️⃣ Decoy Scan
Envia pacotes com IPs falsos para dificultar rastreamento.

**Comando:**
```bash
sudo python3 portscan.py <IP> -decoy -p 1-1000
```

**Resultado do Scan:**

![Decoy Scan - Resultado](imgs/decoy.png)

**Captura no Wireshark:**

![Decoy Scan - Wireshark](imgs/decoy_wireshark.png)

---

## 📝 Exemplos 

```bash
# Scan SYN em porta específica
sudo python3 portscan.py 192.168.1.1 -p 80

# Scan UDP em range de portas
sudo python3 portscan.py scanme.nmap.org -udp -p 53-100

# Scan ACK para detectar firewall
sudo python3 portscan.py 10.0.0.1 -ack -p 1-1024

# Decoy scan com IPs falsos
sudo python3 portscan.py 192.168.1.1 -decoy -p 22-443
```

---


