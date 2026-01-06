import sys
import socket
import time
import random
import warnings
import logging

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.layers.arp").setLevel(logging.ERROR)

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf
except ImportError as e:
    print("[!] Erro: Scapy não está instalado")
    print("[?] Execute: pip install scapy")
    sys.exit(1)
except Exception as e:
    # Em caso de erro de carregamento (compatibilidade), tenta importar direto
    try:
        from scapy.packet import Packet
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.sendrecv import sr1, send
        from scapy import conf
    except ImportError:
        print("[!] Erro ao carregar Scapy")
        sys.exit(1)

# Desativa verbosidade do Scapy
conf.verb = 0


# Configuração dos tipos de scan disponíveis
TIPOS_SCAN = {
    '-syn': ('syn', 'SYN Scan'),
    '-udp': ('udp', 'UDP Scan'),
    '-ack': ('ack', 'ACK Scan')
}



def main():
    if len(sys.argv) < 2:
        print("[!] Erro: Nenhum argumento fornecido!")
        print("[?] Digite: python portscan.py -help para ajuda.")
        sys.exit(1)
    
    input_usuario = sys.argv[1]
    if input_usuario == '-help':
        menu_help()
        sys.exit(0)

    try:
        ip_alvo = validar_e_resolver_ip(input_usuario)
        
        print(f"\n[*] Verificando disponibilidade do host {ip_alvo}...", end="", flush=True)
        if not verificar_host_vivo(ip_alvo):
            print("\n[!] Erro: Host não respondeu a ping (offline ou firewall bloqueia ICMP)")
            print("[!] Scan cancelado.")
            return
        else:
            print(" ✓ Host disponível\n")
        
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
                    print("[!] Erro: faltou o valor após -p!")
                    print("[?] Exemplos: -p 80 | -p 80-443 | -p 80,443,22")
                    sys.exit(1)
                
                valor = args[i + 1]
                try:
                    tipo_porta, dados_porta = validar_portas(valor)
                    if tipo_porta == 'lista':
                        lista_portas = dados_porta
                    elif tipo_porta == 'intervalo':
                        inicio_porta, fim_porta = dados_porta
                        lista_portas = None
                    else:  # 'unica'
                        inicio_porta = fim_porta = dados_porta
                        lista_portas = None
                except ValueError as ve:
                    print(f"[!] Erro no argumento -p: {ve}")
                    sys.exit(1)
                i += 2
                continue
            i += 1

        if usar_decoy:
            scan_nome += f' com Decoy ({qtd_decoy} IPs)'
        if lista_portas:
            portas_str = ','.join(map(str, lista_portas))
        else:
            portas_str = f"{inicio_porta}-{fim_porta}"
        
        print(f"[*] Iniciando {scan_nome} em {ip_alvo} | Portas: {portas_str}\n")
        total_portas, portas_abertas = percorre_portas(inicio_porta, fim_porta, tipo_scan, ip_alvo, usar_decoy, qtd_decoy, lista_portas)
        print(f"\n[*] Scan concluído: {portas_abertas} porta(s) aberta(s) de {total_portas} escaneada(s)")
        if portas_abertas == 0:
            print(f"[!] Resto FECHADA")
                
    except ValueError as ve:
        print(f"[!] Erro: {ve}")
        return
    except socket.gaierror as ge:
        print(f"[!] Erro de DNS: Não foi possível resolver o domínio '{input_usuario}'")
        return
    except KeyboardInterrupt:
        print("\n[!] Scan interrompido pelo usuário (Ctrl+C).")
        return
    except Exception as e:
        print(f"[!] Erro inesperado: {type(e).__name__}: {e}")
        return



def validar_e_resolver_ip(entrada):
    """Valida e resolve IP ou domínio com tratamento robusto"""
    entrada = entrada.strip()
    
    if not entrada:
        raise ValueError("Entrada vazia fornecida")
    
    partes = entrada.split('.')
    if len(partes) == 4:
        try:
            for i, parte in enumerate(partes):
                num = int(parte)
                if num < 0 or num > 255:
                    raise ValueError(f"IP '{entrada}' inválido: octeto {i+1} = {num} (deve ser 0-255)")
            return entrada
        except ValueError as e:
            if "invalid literal" in str(e).lower():
                pass
            else:
                raise
    
    try:
        ip_resolvido = socket.gethostbyname(entrada)
        return ip_resolvido
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{entrada}' (IP ou domínio inválido)")
    except socket.error as e:
        raise ValueError(f"Erro ao resolver '{entrada}': {e}")


def verificar_host_vivo(ip_alvo, timeout=2):
    """Verifica se host está disponível usando ICMP Echo (ping)"""
    try:
        pacote = IP(dst=ip_alvo) / ICMP()
        resposta = sr1(pacote, timeout=timeout, verbose=0, retry=0)
        return resposta is not None
    except:
        return False

def percorre_portas(inicio_porta, fim_porta, tipo_scan, ip_alvo, usar_decoy=False, qtd_decoy=2, lista_portas=None):
    """Itera sobre as portas e executa o scan escolhido"""
    SCANS = {'syn': scan_syn, 'udp': scan_udp, 'ack': scan_ack}
    funcao_scan = SCANS.get(tipo_scan, scan_syn)
    
    portas_abertas = 0
    
    if lista_portas:
        total_portas = len(lista_portas)
        for porta in lista_portas:
            resultado = funcao_scan(ip_alvo, porta, usar_decoy, qtd_decoy)
            if resultado:
                portas_abertas += 1
            time.sleep(0.1)
    else:
        total_portas = fim_porta - inicio_porta + 1
        for porta in range(inicio_porta, fim_porta + 1):
            resultado = funcao_scan(ip_alvo, porta, usar_decoy, qtd_decoy)
            if resultado:
                portas_abertas += 1
            time.sleep(0.1)
    
    return total_portas, portas_abertas


def scan_syn(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    """SYN Scan - Técnica stealth (half-open) para detectar portas abertas"""
    try:
        if usar_decoy:
            enviar_pacotes_decoy(ip_alvo, porta, qtd_decoy=qtd_decoy)
            time.sleep(0.5)
        resposta = enviar_pacote(ip_alvo, porta, 'S', timeout=3)
        
        if resposta is None:
            return False
        
        if resposta.haslayer(TCP):
            flags_recebidas = resposta[TCP].flags
            
            if flags_recebidas == 0x12:  # SYN-ACK = porta aberta
                # RST com seq=ack fecha stealth sem log (não completa 3-way handshake)
                try:
                    send(IP(dst=ip_alvo) / TCP(dport=porta, flags='R', seq=resposta[TCP].ack), verbose=0)
                except:
                    pass
                
                servico = obter_servico(porta, 'tcp')
                modo = f" (decoy)" if usar_decoy else ""
                print(f"[+] Porta {porta}/tcp ABERTA - Serviço: {servico}{modo}")
                return True
            
            elif flags_recebidas == 0x14 or flags_recebidas == 0x04:  # RST-ACK ou RST puro
                return False
        
        return False
    
    except Exception as e:
        return False


def scan_udp(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    """UDP Scan com payloads específicos (nmap-style)"""
    try:
        if usar_decoy:
            enviar_pacotes_decoy(ip_alvo, porta, protocolo='udp', qtd_decoy=qtd_decoy)
        
        # Payload é crucial: UDP ignora pacotes vazios (serviço não responde)
        payload = gerar_payload_udp(porta)
        resposta = enviar_pacote_udp_com_payload(ip_alvo, porta, payload, timeout=4)
        servico = obter_servico(porta, 'udp')
        modo = f" (decoy)" if usar_decoy else ""

        if resposta is None:
            return False

        if resposta.haslayer(UDP):
            print(f"[+] Porta {porta}/udp ABERTA - Serviço: {servico}{modo}")
            return True

        if resposta.haslayer(ICMP):
            icmp = resposta[ICMP]
            # ICMP type 3 code 3 = port unreachable (porta fechada)
            if int(icmp.type) == 3 and int(icmp.code) == 3:
                return False
            return False
        
        return False
    
    except Exception as e:
        return False


def scan_ack(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    """ACK Scan - Detecta firewall, não identifica abertas/fechadas"""
    try:
        if usar_decoy:
            enviar_pacotes_decoy(ip_alvo, porta, flags='A', qtd_decoy=qtd_decoy)
        
        resposta = enviar_pacote(ip_alvo, porta, 'A', timeout=3)
        modo = f" (decoy)" if usar_decoy else ""
        
        if resposta is None:
            print(f"[!] Porta {porta}/tcp FILTRADA (sem resposta){modo}")
            return False

        if resposta.haslayer(TCP):
            flags = int(resposta[TCP].flags)
            
            # RST (0x04) ou RST-ACK (0x14) = firewall não bloqueia
            if flags == 0x04 or flags == 0x14:
                print(f"[?] Porta {porta}/tcp NAO-FILTRADA (respondeu RST){modo}")
                return True

        if resposta.haslayer(ICMP):
            icmp = resposta[ICMP]
            # ICMP type 3 codes 1,2,3,9,10,13 = host/port unreachable (filtrado)
            if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 3, 9, 10, 13):
                print(f"[!] Porta {porta}/tcp FILTRADA (ICMP code {int(icmp.code)}){modo}")
                return False
        
        return False
    
    except Exception as e:
        return False


def enviar_pacote(ip_alvo, porta, flags, protocolo='tcp', timeout=5):
    try:
        if protocolo == 'tcp':
            pacote = IP(dst=ip_alvo) / TCP(dport=porta, flags=flags)
        else:
            pacote = IP(dst=ip_alvo) / UDP(dport=porta)
        
        # retry=0 evita travamento, sr1 retorna None se timeout
        resposta = sr1(pacote, timeout=timeout, verbose=0, retry=0)
        return resposta
    
    except (OSError, ValueError, Exception):
        return None


def enviar_pacote_udp_com_payload(ip_alvo, porta, payload, timeout=5):
    """Envia UDP com payload (nmap-style service detection)"""
    try:
        pacote = IP(dst=ip_alvo) / UDP(dport=porta) / payload
        resposta = sr1(pacote, timeout=timeout, verbose=0, retry=0)
        return resposta
    except:
        return None


def gerar_payload_udp(porta):
    """Payloads baseados em nmap-service-probes - crucial para detecção UDP"""
    from scapy.packet import Raw
    
    payloads_porta = {
        53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS
        67: b'\x01\x01\x06\x00' + b'\x00' * 56,  # DHCP
        111: b'\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0',  # Portmap
        123: b'\x1b' + b'\x00' * 47,  # NTP
        137: b'\x80\x84\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # NetBIOS
        138: b'\x80\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # NetBIOS
        161: b'\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x00\x00\x00\x00',  # SNMP
        162: b'\x30\x3d\x02\x01\x00\x04\x06public\xa7\x31\x02\x04\x00\x00\x00\x00',  # SNMP
        445: b'\x00' * 4 + b'\xff' + b'SMB' + b'\x00' * 8,  # SMB
        500: b'\x00' * 4,  # IKE
        1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n',  # SSDP
    }
    
    return Raw(load=payloads_porta.get(porta, b'\x00' * 8))


def enviar_pacotes_decoy(ip_alvo, porta, flags='S', protocolo='tcp', qtd_decoy=2):
    """Decoy packets ofuscam o scan (IDS evasion)"""
    try:
        for _ in range(qtd_decoy):
            ip_falso = gerar_ip_falso()
            
            try:
                if protocolo == 'tcp':
                    pacote_decoy = IP(src=ip_falso, dst=ip_alvo) / TCP(dport=porta, flags=flags)
                else:
                    pacote_decoy = IP(src=ip_falso, dst=ip_alvo) / UDP(dport=porta)
                
                send(pacote_decoy, verbose=0)
                time.sleep(0.02)
            except:
                pass  
    
    except:
        pass 


def validar_portas(valor):
    valor = valor.strip()
    
    if not valor:
        raise ValueError("Valor de porta não pode estar vazio")
    
    if ',' in valor:
        portas_str = valor.split(',')
        portas_validadas = []
        
        for porta_str in portas_str:
            porta_str = porta_str.strip()
            if not porta_str:
                raise ValueError("Porta vazia detectada em lista")
            
            try:
                p = int(porta_str)
            except ValueError:
                raise ValueError(f"'{porta_str}' não é um número válido")
            
            if p < 1 or p > 65535:
                raise ValueError(f'Porta {p} deve estar entre 1 e 65535')
            
            portas_validadas.append(p)
        
        if len(portas_validadas) == 0:
            raise ValueError("Nenhuma porta válida fornecida")
        
        return 'lista', portas_validadas
    
    elif '-' in valor:
        partes = valor.split('-')
        
        if len(partes) != 2:
            raise ValueError('Use o formato: inicio-fim (ex: 80-443)')
        
        try:
            a, b = int(partes[0].strip()), int(partes[1].strip())
        except ValueError:
            raise ValueError(f"'{valor}' não contém números válidos no intervalo")
        
        if a < 1 or a > 65535 or b < 1 or b > 65535:
            raise ValueError('Portas devem estar entre 1 e 65535')
        
        if a > b:
            raise ValueError(f'Intervalo inválido: {a} é maior que {b}')
        
        return 'intervalo', (a, b)
    else:
        try:
            p = int(valor)
        except ValueError:
            raise ValueError(f"'{valor}' não é um número válido")
        
        if p < 1 or p > 65535:
            raise ValueError('Porta deve estar entre 1 e 65535')
        
        return 'unica', p


def gerar_ip_falso():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def obter_servico(porta, protocolo):
    try:
        return socket.getservbyport(porta, protocolo)
    except:
        return "desconhecido"


def menu_help():
    print("\n" + "="*80)
    print("                        PORTSCAN - MENU DE AJUDA")
    print("="*80 + "\n")
    
    print("Uso:")
    print("  python portscan.py <IP> [opções]\n")
    
    print("Tipos de Scan:")
    print("  -syn     Scan SYN (padrão - stealth scan)")
    print("  -udp     Scan UDP (detecta portas UDP)")
    print("  -ack     Scan ACK (detecta firewall)\n")
    
    print("Modificadores:")
    print("  -decoy              Adiciona IPs falsos")
    print("  -decoy <número>     Define quantidade de IPs decoy (ex: -decoy 48)")
    print("  Padrão decoy: 2 IPs\n")
    
    print("Portas:")
    print("  -p <porta>          Porta única (ex: -p 22)")
    print("  -p <início-fim>     Intervalo (ex: -p 1-1024)")
    print("  -p <p1,p2,p3>       Múltiplas portas (ex: -p 80,443,22,8080)")
    print("  Padrão: 1-1024\n")
    
    print("Exemplos:")
    print("  python portscan.py 192.168.1.1")
    print("  python portscan.py scanme.nmap.org -p 80-443")
    print("  python portscan.py 10.0.0.1 -udp -p 53")
    print("  python portscan.py 192.168.1.1 -syn -decoy -p 80")
    print("  python portscan.py 192.168.1.1 -syn -decoy 48 -p 1-100")
    print("  python portscan.py 10.0.0.1 -udp -decoy 10 -p 53,123")
    print("  python portscan.py 10.0.0.1 -ack -decoy 100\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrompido pelo usuário (Ctrl+C).")
        sys.exit(0)
