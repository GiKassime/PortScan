import sys
import socket
import time
import random
import warnings
import logging
import re

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.layers.arp").setLevel(logging.ERROR)

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf, Raw
except ImportError as e:
    print("\nA biblioteca 'scapy' não está instalada.")
    print("[-] Para corrigir, execute: pip install scapy")
    print("[-] Se estiver no Windows, instale também o Npcap: https://npcap.com/\n")
    sys.exit(1)
except Exception as e:
    try:
        from scapy.packet import Packet
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.packet import Raw
        from scapy.sendrecv import sr1, send
        from scapy import conf
    except ImportError:
        print("[!] Erro ao carregar Scapy")
        sys.exit(1)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    CORES_DISPONIVEIS = True
except ImportError:
    class Fore:
        GREEN = RED = YELLOW = CYAN = BLUE = MAGENTA = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''
    CORES_DISPONIVEIS = False

conf.verb = 0

TIPOS_SCAN = {
    '-syn': ('syn', 'SYN Scan'),
    '-udp': ('udp', 'UDP Scan'),
    '-ack': ('ack', 'ACK Scan')
}

def main():
    if len(sys.argv) < 2:
        print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro: Nenhum argumento fornecido!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[?] Digite: python3 portscan.py -help para ajuda.{Style.RESET_ALL}")
        sys.exit(1)
    
    input_usuario = sys.argv[1]
    
    if input_usuario == '-help':
        menu_help()
        sys.exit(0)

    try:
        ip_alvo = validar_e_resolver_ip(input_usuario)
        
        print(f"\n{Fore.CYAN}[*] Verificando disponibilidade do host {ip_alvo}...{Style.RESET_ALL}", end="", flush=True)
        if not verificar_host_vivo(ip_alvo):
            print(f"\n{Fore.RED}{Style.BRIGHT}[✗] Erro: Host não respondeu a ping (offline ou firewall bloqueia ICMP){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Scan cancelado.{Style.RESET_ALL}")
            return
        else:
            print(f" {Fore.GREEN}✓ Host disponível{Style.RESET_ALL}\n")

        inicio_porta = 1
        fim_porta = 1024
        lista_portas = None
        tipo_scan = 'syn'
        usar_decoy = False
        qtd_decoy = 2
        scan_nome = 'SYN Scan (Padrão)'

        args = sys.argv[2:]
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg in TIPOS_SCAN:
                tipo_scan, scan_nome = TIPOS_SCAN[arg]
                i += 1
                continue
            
            if arg == '-decoy':
                usar_decoy = True
                if i + 1 < len(args) and args[i + 1].isdigit():
                    qtd_decoy = int(args[i + 1])
                    i += 2
                else:
                    i += 1
                continue

            if arg == '-p':
                if i + 1 >= len(args):
                    print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro: faltou o valor após -p!{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[?] Exemplos: -p 80 | -p 80-443 | -p 80,443,22{Style.RESET_ALL}")
                    sys.exit(1)
                
                valor = args[i + 1]
                try:
                    tipo_porta, dados_porta = validar_portas(valor)
                    if tipo_porta == 'lista':
                        lista_portas = dados_porta
                    elif tipo_porta == 'intervalo':
                        inicio_porta, fim_porta = dados_porta
                        lista_portas = None
                    else:
                        inicio_porta = fim_porta = dados_porta
                        lista_portas = None
                except ValueError as ve:
                    print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro no argumento -p: {ve}{Style.RESET_ALL}")
                    sys.exit(1)
                i += 2
                continue

            if arg.startswith('-'):
                print(f"{Fore.YELLOW}[!] Aviso: argumento desconhecido '{arg}' será ignorado.{Style.RESET_ALL}")
            i += 1

        if usar_decoy:
            scan_nome += f' {Fore.MAGENTA}com Decoy ({qtd_decoy} IPs){Style.RESET_ALL}'
        
        if lista_portas:
            portas_str = ','.join(map(str, lista_portas))
        else:
            portas_str = f"{inicio_porta}-{fim_porta}"
        
        print(f"{Fore.CYAN}{Style.BRIGHT}[*] Iniciando {scan_nome} {Fore.CYAN}em {Fore.GREEN}{ip_alvo}{Fore.CYAN} | Portas: {Fore.YELLOW}{portas_str}{Style.RESET_ALL}\n")
        total_portas, portas_abertas = percorre_portas(inicio_porta, fim_porta, tipo_scan, ip_alvo, usar_decoy, qtd_decoy, lista_portas)
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] Scan concluído: {Fore.GREEN}{portas_abertas}{Fore.CYAN} porta(s) aberta(s) de {total_portas} escaneada(s){Style.RESET_ALL}")
        if portas_abertas == 0:
            print(f"{Fore.YELLOW}[!] Resto FECHADA{Style.RESET_ALL}")
                
    except ValueError as ve:
        print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro: {ve}{Style.RESET_ALL}")
        return
    except socket.gaierror as ge:
        print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro de DNS: Não foi possível resolver o domínio '{input_usuario}'{Style.RESET_ALL}")
        return
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[⚠] Scan interrompido pelo usuário (Ctrl+C).{Style.RESET_ALL}")
        return
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro inesperado: {type(e).__name__}: {e}{Style.RESET_ALL}")
        return


def validar_e_resolver_ip(input_usuario):
    padrao_ipv4 = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    
    if re.match(padrao_ipv4, input_usuario):
        octetos = list(map(int, input_usuario.split('.')))
        for i, octeto in enumerate(octetos, 1):
            if octeto < 0 or octeto > 255:
                raise ValueError(f"Octeto {i} inválido: {octeto} deve estar entre 0-255")
        return input_usuario
    else:
        try:
            ip = socket.gethostbyname(input_usuario)
            return ip
        except socket.gaierror:
            raise socket.gaierror(f"Não foi possível resolver o domínio '{input_usuario}'")


def verificar_host_vivo(ip_alvo, timeout=2):
    try:
        conf.verb = 0
        pacote = IP(dst=ip_alvo)/ICMP()
        resposta = sr1(pacote, timeout=timeout, retry=0)
        return resposta is not None
    except Exception:
        return False


def percorre_portas(inicio_porta, fim_porta, tipo_scan, ip_alvo, usar_decoy=False, qtd_decoy=2, lista_portas=None):
    SCANS = {'syn': scan_syn, 'udp': scan_udp, 'ack': scan_ack}
    funcao_scan = SCANS.get(tipo_scan, scan_syn)  
    
    total_portas = 0
    portas_abertas = 0
    
    if lista_portas:
        for porta in lista_portas:
            total_portas += 1
            resultado = funcao_scan(ip_alvo, porta, usar_decoy, qtd_decoy)
            if resultado:
                portas_abertas += 1
            time.sleep(0.1)
    else:
        for porta in range(inicio_porta, fim_porta + 1):
            total_portas += 1
            resultado = funcao_scan(ip_alvo, porta, usar_decoy, qtd_decoy)
            if resultado:
                portas_abertas += 1
            time.sleep(0.1)
    
    return total_portas, portas_abertas


def scan_syn(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    if usar_decoy:
        enviar_pacotes_decoy(ip_alvo, porta, qtd_decoy=qtd_decoy)
        time.sleep(1)
    
    resposta = enviar_pacote(ip_alvo, porta, 'S')
    if resposta is None:
        return False
    
    # SYN-ACK (0x12) = porta aberta
    if resposta.haslayer(TCP) and resposta[TCP].flags == 0x12:
        enviar_pacote(ip_alvo, porta, 'R', seq=resposta[TCP].ack)
        servico = obter_servico(porta, 'tcp')
        modo = formatar_modo_decoy(usar_decoy)
        print(f"{Fore.GREEN}[+] Porta {porta}/tcp aberta - Serviço: {servico}{modo}{Style.RESET_ALL}")
        return True
    
    return False

def scan_udp(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    if usar_decoy:
        enviar_pacotes_decoy(ip_alvo, porta, protocolo='udp', qtd_decoy=qtd_decoy)
    
    payload = gerar_payload_udp(porta)
    resposta = enviar_pacote_udp_com_payload(ip_alvo, porta, payload)
    
    if resposta is None:
        servico = obter_servico(porta, 'udp')
        modo = formatar_modo_decoy(usar_decoy)
        print(f"{Fore.CYAN}[?] Porta {porta}/udp aberta|filtrada - Serviço: {servico}{modo}{Style.RESET_ALL}")
        return True

    if resposta.haslayer(UDP):
        servico = obter_servico(porta, 'udp')
        modo = formatar_modo_decoy(usar_decoy)
        print(f"{Fore.GREEN}[+] Porta {porta}/udp aberta - Serviço: {servico}{modo}{Style.RESET_ALL}")
        return True

    # ICMP type 3, code 3 = Destination Unreachable (porta fechada)
    if resposta.haslayer(ICMP):
        icmp = resposta[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) == 3:
            return False
    
    return False

def scan_ack(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    if usar_decoy:
        enviar_pacotes_decoy(ip_alvo, porta, flags='A', qtd_decoy=qtd_decoy)
    
    resposta = enviar_pacote(ip_alvo, porta, 'A')
    modo = formatar_modo_decoy(usar_decoy)
    
    if resposta is None:
        print(f"{Fore.YELLOW}[!] Porta {porta}/tcp filtrada (sem resposta){modo}{Style.RESET_ALL}")
        return False

    if resposta.haslayer(TCP):
        flags = int(resposta[TCP].flags)
        if flags in (0x04, 0x14):
            print(f"{Fore.CYAN}[?] Porta {porta}/tcp não-filtrada (respondeu RST){modo}{Style.RESET_ALL}")
            return True

    if resposta.haslayer(ICMP):
        icmp = resposta[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 3, 9, 10, 13):
            print(f"{Fore.YELLOW}[!] Porta {porta}/tcp filtrada (ICMP code {int(icmp.code)}){Style.RESET_ALL}")
            return False
    
    return False
    
def enviar_pacote(ip_alvo, porta, flags, protocolo='tcp', seq=None):
    if protocolo == 'tcp':
        if seq is not None:
            pacote = IP(dst=ip_alvo)/TCP(dport=porta, flags=flags, seq=seq)
        else:
            pacote = IP(dst=ip_alvo)/TCP(dport=porta, flags=flags)
    else:
        pacote = IP(dst=ip_alvo)/UDP(dport=porta)
    
    resposta = sr1(pacote, timeout=3, retry=0, verbose=0)
    return resposta


def enviar_pacote_udp_com_payload(ip_alvo, porta, payload, timeout=4):
    try:
        pacote = IP(dst=ip_alvo)/UDP(dport=porta)/payload
        resposta = sr1(pacote, timeout=timeout, retry=0, verbose=0)
        return resposta
    except Exception:
        return None


def gerar_payload_udp(porta):
    payloads = {
        53: Raw(b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00'),  # DNS
        67: Raw(b'\x01\x01\x06\x00' + b'\x00' * 12),  # DHCP
        111: Raw(b'\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02'),  # Portmap
        123: Raw(b'\x1b' + b'\x00' * 47),  # NTP
        137: Raw(b'\x89\x00\x00\x00\x00\x00\x00\x00\x00'),  # NetBIOS
        138: Raw(b'\x89\x00\x00\x00\x00\x00\x00\x00\x00'),  # NetBIOS
        161: Raw(b'\x30\x26\x02\x01\x00\x04\x06public'),  # SNMP
        162: Raw(b'\x30\x26\x02\x01\x00\x04\x06public'),  # SNMP Trap
        445: Raw(b'\x82\x00\x00\x00'),  # SMB
        500: Raw(b'\x00' * 8),  # IKE
        1900: Raw(b'M-SEARCH * HTTP/1.1\r\n'),  # SSDP
    }
    return payloads.get(porta, Raw(b'\x00' * 8))

def enviar_pacotes_decoy(ip_alvo, porta, flags='S', protocolo='tcp', qtd_decoy=2):
    ips_decoy = [gerar_ip_falso() for _ in range(qtd_decoy)]
    
    for ip_falso in ips_decoy:
        if protocolo == 'tcp':
            pacote_decoy = IP(src=ip_falso, dst=ip_alvo)/TCP(dport=porta, flags=flags)
        else:
            pacote_decoy = IP(src=ip_falso, dst=ip_alvo)/UDP(dport=porta)
        send(pacote_decoy, verbose=0) 
        time.sleep(0.05) 


def validar_portas(valor):
    if ',' in valor:
        portas = valor.split(',')
        portas_validadas = []
        for porta_str in portas:
            porta_str = porta_str.strip()
            try:
                p = int(porta_str)
            except ValueError:
                raise ValueError(f"'{porta_str}' não é um número válido")
            
            if p < 1 or p > 65535:
                raise ValueError(f'Porta {p} deve estar entre 1 e 65535')
            portas_validadas.append(p)
        
        return 'lista', portas_validadas
    
    elif '-' in valor:
        partes = valor.split('-')
        if len(partes) != 2:
            raise ValueError('Use o formato: inicio-fim (ex: 80-443)')
        try:
            a, b = int(partes[0]), int(partes[1])
        except ValueError:
            raise ValueError(f"'{valor}' não contém números válidos")
        
        if a < 1 or a > 65535 or b < 1 or b > 65535:
            raise ValueError('Portas devem estar entre 1 e 65535')
        
        return 'intervalo', (min(a, b), max(a, b))
    else:
        try:
            p = int(valor)
        except ValueError:
            raise ValueError(f"'{valor}' não é um número inteiro válido")
        
        if p < 1 or p > 65535:
            raise ValueError('Porta deve estar entre 1 e 65535')
        
        return 'unica', p

def formatar_modo_decoy(usar_decoy):
    return f" {Fore.MAGENTA}(decoy){Style.RESET_ALL}" if usar_decoy else ""

def gerar_ip_falso():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def obter_servico(porta, protocolo):
    try:
        return socket.getservbyport(porta, protocolo)
    except:
        return "desconhecido"

def menu_help():
    print(f"\n{Fore.CYAN}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════════════════════╗")
    print(f"║                          {Fore.GREEN}PORTSCAN - MENU DE AJUDA{Fore.CYAN}                          ║")
    print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}Uso:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python3 portscan.py {Fore.GREEN}<IP> {Fore.CYAN}[opções]{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}Tipos de Scan:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}-syn{Style.RESET_ALL}     Scan SYN {Fore.GREEN}(padrão - stealth scan){Style.RESET_ALL}")
    print(f"  {Fore.CYAN}-udp{Style.RESET_ALL}     Scan UDP {Fore.CYAN}(detecta portas UDP){Style.RESET_ALL}")
    print(f"  {Fore.CYAN}-ack{Style.RESET_ALL}     Scan ACK {Fore.YELLOW}(detecta firewall){Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}Modificadores:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}-decoy{Style.RESET_ALL}          Adiciona IPs falsos {Fore.MAGENTA}(combinável com qualquer scan){Style.RESET_ALL}")
    print(f"  {Fore.CYAN}-decoy{Style.RESET_ALL} {Fore.MAGENTA}<número>{Style.RESET_ALL}   Define quantidade de IPs decoy (ex: {Fore.WHITE}-decoy 48{Style.RESET_ALL})")
    print(f"  {Fore.YELLOW}Padrão decoy: 2 IPs{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}Portas:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}-p{Style.RESET_ALL} {Fore.MAGENTA}<porta>{Style.RESET_ALL}         Porta única (ex: {Fore.WHITE}-p 22{Style.RESET_ALL})")
    print(f"  {Fore.CYAN}-p{Style.RESET_ALL} {Fore.MAGENTA}<início-fim>{Style.RESET_ALL}   Intervalo (ex: {Fore.WHITE}-p 1-1024{Style.RESET_ALL})")
    print(f"  {Fore.CYAN}-p{Style.RESET_ALL} {Fore.MAGENTA}<p1,p2,p3>{Style.RESET_ALL}     Múltiplas portas (ex: {Fore.WHITE}-p 80,443,22,8080{Style.RESET_ALL})")
    print(f"  {Fore.YELLOW}Padrão: 1-1024{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}Exemplos:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python3 portscan.py 192.168.1.1{Style.RESET_ALL}                              {Fore.GREEN}# SYN scan padrão{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python3 portscan.py scanme.nmap.org -p 80-443{Style.RESET_ALL}               {Fore.GREEN}# SYN scan em portas específicas{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python3 portscan.py 10.0.0.1 -udp -p 53{Style.RESET_ALL}                     {Fore.GREEN}# UDP scan{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python3 portscan.py 192.168.1.1 -syn -decoy -p 80{Style.RESET_ALL}           {Fore.GREEN}# SYN com decoy (2 IPs){Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python3 portscan.py 192.168.1.1 -syn -decoy 48 -p 1-100{Style.RESET_ALL}     {Fore.GREEN}# SYN com 48 IPs decoy{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python3 portscan.py 10.0.0.1 -udp -decoy 10 -p 53,123{Style.RESET_ALL}       {Fore.GREEN}# UDP com 10 IPs decoy{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python3 portscan.py 10.0.0.1 -ack -decoy 100{Style.RESET_ALL}                {Fore.GREEN}# ACK scan com 100 IPs decoy{Style.RESET_ALL}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[⚠] Scan interrompido pelo usuário (Ctrl+C).{Style.RESET_ALL}")
        sys.exit(0)