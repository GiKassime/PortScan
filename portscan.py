import sys
import socket
import time
import random

# Color output (colorama)cores no texto
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
except Exception:
    # se n der certo vai ser cores msm
    class _Dummy:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ''
    class _StyleDummy:
        RESET_ALL = ''
        BRIGHT = ''
    Fore = _Dummy()
    Style = _StyleDummy()


def _c(text, color='', bright=False):
    #função para colorir textos
    prefix = ''
    if bright:
        prefix += Style.BRIGHT
    prefix += color or ''
    return f"{prefix}{text}{Style.RESET_ALL}"

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf
except ImportError as e:
    print(_c("[!] Erro: Scapy não está instalado ou não foi encontrado no ambiente atual", Fore.RED, bright=True))
    print(_c(f"[?] Detalhe: {e}", Fore.YELLOW))
    print(_c("[?] Solução: instale em um venv (`python3 -m venv .venv && .venv/bin/pip install scapy`) ou instale o pacote do sistema: `sudo apt install python3-scapy`", Fore.CYAN))
    sys.exit(1)

# Desativa verbosidade do Scapy
conf.verb = 0
# array de tipos de scan
TIPOS_SCAN = {
    '-syn': ('syn', 'SYN Scan'),
    '-udp': ('udp', 'UDP Scan'),
    '-ack': ('ack', 'ACK Scan')
}

def main():
    if len(sys.argv) < 2:
        print(_c("[!] Erro: Nenhum argumento fornecido!", Fore.RED, bright=True))
        print(_c("[?] Digite: python portscan.py -help para ajuda.", Fore.CYAN))
        sys.exit(1)
    
    input_usuario = sys.argv[1]
    if input_usuario == '-help':
        menu_help()
        sys.exit(0)

    try:
        ip_alvo = validar_e_resolver_ip(input_usuario)
        print(_c(f"\n[*] Verificando disponibilidade do host {ip_alvo}...", Fore.CYAN), end="", flush=True)
        
        if not verificar_host_vivo(ip_alvo):
            print(_c("\n[!] Erro: Host não respondeu a ping (offline ou firewall bloqueia ICMP)", Fore.RED, bright=True))
            print(_c("[!] Scan cancelado.", Fore.YELLOW))
            sys.exit(0)
        
        print(_c(" ✓ Host disponível\n", Fore.GREEN, bright=True))

        # Configurações padrão
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
                # Lógica ternária para verificar o próximo argumento
                if i + 1 < len(args) and args[i + 1].isdigit():
                    qtd_decoy = int(args[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            
            if arg == '-p':
                if i + 1 >= len(args):
                    print(_c("[!] Erro: faltou o valor após -p!", Fore.RED, bright=True))
                    sys.exit(1)
                
                valor = args[i + 1]
                tipo_porta, dados_porta = validar_portas(valor)
                
                lista_portas = None 
                
                if tipo_porta == 'lista':
                    lista_portas = dados_porta
                elif tipo_porta == 'intervalo':
                    inicio_porta, fim_porta = dados_porta
                else:  # unica
                    inicio_porta = fim_porta = dados_porta
                
                i += 2
                continue
            
            # Caso não entre em nenhum if, é argumento inválido
            print(_c(f"[!] Aviso: Argumento desconhecido ignorado: {arg}", Fore.YELLOW))
            i += 1

        if usar_decoy:
            scan_nome += f' com Decoy ({qtd_decoy} IPs)'
        
        # Lógica de exibição das portas
        if lista_portas:
            portas_str = ','.join(map(str, lista_portas))
        else:
            portas_str = f"{inicio_porta}-{fim_porta}"
        
        print(_c(f"[*] Iniciando {scan_nome} em {ip_alvo} | Portas: {portas_str}\n", Fore.CYAN, bright=True))
        
        # Chama a função otimizada que fizemos antes
        total_portas, portas_abertas = percorre_portas(inicio_porta, fim_porta, tipo_scan, ip_alvo, usar_decoy, qtd_decoy, lista_portas)
        
        print(_c(f"\n[*] Scan concluído: {portas_abertas} porta(s) aberta(s) de {total_portas} escaneada(s)", Fore.CYAN))
        if portas_abertas == 0:
            print(_c(f"[!] Nenhuma porta aberta encontrada.", Fore.YELLOW, bright=True))
                
    except ValueError as ve:
        print(_c(f"[!] Erro: {ve}", Fore.RED, bright=True))
        sys.exit(1) # Use sys.exit em vez de return na main
    except KeyboardInterrupt:
        print(_c("\n[!] Scan interrompido pelo usuário (Ctrl+C).", Fore.YELLOW, bright=True))
        sys.exit(0)
    except Exception as e:
        print(_c(f"[!] Erro inesperado: {type(e).__name__}: {e}", Fore.RED, bright=True))
        sys.exit(1)

def validar_e_resolver_ip(entrada):
    entrada = entrada.strip()

    if not entrada:
        raise ValueError("Entrada vazia fornecida")
    
    partes = entrada.split('.')
    if len(partes) == 4:
        try:
            for i, parte in enumerate(partes):
                    if not parte.isdigit():
                        raise ValueError(f"IP '{entrada}' malformado: octeto {i+1} ('{parte}') contém letras")
                    
                    num = int(parte)
                    if num < 0 or num > 255:
                        raise ValueError(f"IP '{entrada}' inválido: octeto {i+1} = {num} (deve ser 0-255)")
                
            return entrada # Se passou por tudo, é um IP válido
        except ValueError as ve:
            raise ve 
    try:
        ip_resolvido = socket.gethostbyname(entrada)
        return ip_resolvido
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{entrada}' (IP ou domínio inválido)")


def verificar_host_vivo(ip_alvo, timeout=2):
    up = False
    resp_icmp = sr1(IP(dst=ip_alvo)/ICMP(), timeout=timeout, verbose=0)
    if resp_icmp:
        up = True 
    return up

def percorre_portas(inicio_porta, fim_porta, tipo_scan, ip_alvo, usar_decoy=False, qtd_decoy=2, lista_portas=None):
    SCANS = {'syn': scan_syn, 'udp': scan_udp, 'ack': scan_ack}
    funcao_scan = SCANS.get(tipo_scan, scan_syn)
    portas_abertas = 0
    
    if tipo_scan == 'udp' and usar_decoy:
        print(_c("[*] Nota: Scan UDP não utiliza pacotes decoy.", Fore.YELLOW))
        usar_decoy = False
    
    iteravel_portas = lista_portas if lista_portas else range(inicio_porta, fim_porta + 1)
    total_portas = len(iteravel_portas)
    
    # Loop único das portas
    for porta in iteravel_portas:
        if funcao_scan(ip_alvo, porta, usar_decoy, qtd_decoy):
            portas_abertas += 1
        time.sleep(0.1)
    
    return total_portas, portas_abertas


def scan_syn(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    servico = obter_servico(porta, 'tcp')
    modo = f" (decoy)" if usar_decoy else ""

    if usar_decoy:
        enviar_pacotes_decoy(ip_alvo, porta, qtd_decoy=qtd_decoy)
        time.sleep(0.5) 
    
    resposta = enviar_pacote(ip_alvo, porta, 'S', timeout=3)
    
    # Sem resposta =  FILTRADA
    if resposta is None:
        print(_c(f"[!] Porta {porta}/tcp FILTRADA (sem resposta){modo}", Fore.YELLOW))
        return False
    
    # Resposta TCP 
    if resposta.haslayer(TCP):
        flags_recebidas = resposta[TCP].flags
        
        # SYN/ACK = ABERTA
        if flags_recebidas == 0x12:
            # envia RST para fechar a conexão 
            send(IP(dst=ip_alvo) / TCP(dport=porta, flags='R', seq=resposta[TCP].ack), verbose=0)
            print(_c(f"[+] Porta {porta}/tcp ABERTA - Serviço: {servico}{modo}", Fore.GREEN, bright=True))
            return True
        
        #  RST (0x04) ou RST/ACK (0x14) = FECHADA
        elif flags_recebidas == 0x14 or flags_recebidas == 0x04:
            return False

    # Resposta ICMP = FILTRADA
    elif resposta.haslayer(ICMP):
        icmp = resposta[ICMP]
        #Códigos específicos da tabela DO NMAP
        if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 3, 9, 10, 13):
            print(_c(f"[!] Porta {porta}/tcp FILTRADA (ICMP code {int(icmp.code)}){modo}", Fore.YELLOW))
            return False

    return False
    



def scan_udp(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    resposta = enviar_pacote(ip_alvo, porta,None, protocolo='udp', timeout=4)
    servico = obter_servico(porta, 'udp')

    if resposta is None:
        return False

    if resposta.haslayer(UDP):
        print(_c(f"[+] Porta {porta}/udp ABERTA - Serviço: {servico}", Fore.GREEN, bright=True))
        return True

    if resposta.haslayer(ICMP):
        icmp = resposta[ICMP]
        # ICMP type 3 code 3 = port unreachable (porta fechada)
        if int(icmp.type) == 3 and int(icmp.code) == 3:
            return False
        # na documentação do nmap, esses cófigos indicam filtragem
        if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 9, 10, 13):
            print(_c(f"[!] Porta {porta}/udp FILTRADA (ICMP code {int(icmp.code)})", Fore.YELLOW))
    
    return False


def scan_ack(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    if usar_decoy:
        enviar_pacotes_decoy(ip_alvo, porta, flags='A', qtd_decoy=qtd_decoy)
        
    resposta = enviar_pacote(ip_alvo, porta, 'A', timeout=3)
    modo = f" (decoy)" if usar_decoy else ""
        
    if resposta is None :
        print(_c(f"[!] Porta {porta}/tcp FILTRADA (sem resposta){modo}", Fore.YELLOW))
        return False
        
    if resposta.haslayer(ICMP):
        icmp = resposta[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 3, 9, 10, 13):
            texto = f"(ICMP code {int(icmp.code)})"
            
    if resposta.haslayer(TCP):
        flags = int(resposta[TCP].flags)
        # RST (0x04) ou RST-ACK (0x14) = firewall não bloqueia
        if flags == 0x04 or flags == 0x14:
            print(_c(f"[?] Porta {porta}/tcp NAO-FILTRADA (respondeu RST){modo}", Fore.GREEN))
            return True

    return False
    


def enviar_pacote(ip_alvo, porta, flags, protocolo='tcp', timeout=5):
    if protocolo == 'tcp':
        pacote = IP(dst=ip_alvo) / TCP(dport=porta, flags=flags)
    else:
        pacote = IP(dst=ip_alvo) / UDP(dport=porta)
    # Envia e recebe a resposta 
    resposta = sr1(pacote, timeout=timeout, verbose=0, retry=0)
    return resposta

def enviar_pacotes_decoy(ip_alvo, porta, flags='S', protocolo='tcp', qtd_decoy=2):
   
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

def validar_portas(valor):
    valor = valor.strip()
    
    if not valor:
        raise ValueError("Valor de porta não pode estar vazio")
    #pega as portas separadas por , exemplo 80,22
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
    #pega portas od interlavo ex 1.1041
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
        #se for só uma porta
        return 'unica', p


def gerar_ip_falso():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def obter_servico(porta, protocolo):
    try:
        return socket.getservbyport(porta, protocolo)
    except:
        return "desconhecido"


def menu_help():
    print(_c("\n" + "="*80, Fore.CYAN, bright=True))
    print(_c("                        PORTSCAN - MENU DE AJUDA", Fore.CYAN, bright=True))
    print(_c("="*80 + "\n", Fore.CYAN, bright=True))
    
    print(_c("Uso:", Fore.MAGENTA))
    print(_c("  python portscan.py <IP> [opções]\n", Fore.WHITE))
    
    print(_c("Tipos de Scan:", Fore.MAGENTA))
    print(_c("  -syn     Scan SYN (padrão - stealth scan)", Fore.WHITE))
    print(_c("  -udp     Scan UDP (detecta portas UDP)", Fore.WHITE))
    print(_c("  -ack     Scan ACK (detecta firewall)\n", Fore.WHITE))
    
    print(_c("Modificadores:", Fore.MAGENTA))
    print(_c("  -decoy              Adiciona IPs falsos", Fore.WHITE))
    print(_c("  -decoy <número>     Define quantidade de IPs decoy (ex: -decoy 48)", Fore.WHITE))
    print(_c("  Padrão decoy: 2 IPs\n", Fore.YELLOW))
    
    print(_c("Portas:", Fore.MAGENTA))
    print(_c("  -p <porta>          Porta única (ex: -p 22)", Fore.WHITE))
    print(_c("  -p <início-fim>     Intervalo (ex: -p 1-1024)", Fore.WHITE))
    print(_c("  -p <p1,p2,p3>       Múltiplas portas (ex: -p 80,443,22,8080)", Fore.WHITE))
    print(_c("  Padrão: 1-1024\n", Fore.YELLOW))
    
    print(_c("Exemplos:", Fore.MAGENTA))
    print(_c("  python portscan.py 192.168.1.1", Fore.WHITE))
    print(_c("  python portscan.py scanme.nmap.org -p 80-443", Fore.WHITE))
    print(_c("  python portscan.py 10.0.0.1 -udp -p 53", Fore.WHITE))
    print(_c("  python portscan.py 192.168.1.1 -syn -decoy -p 80", Fore.WHITE))
    print(_c("  python portscan.py 192.168.1.1 -syn -decoy 48 -p 1-100", Fore.WHITE))
    print(_c("  python portscan.py 10.0.0.1 -ack -decoy 100\n", Fore.WHITE))

# permite que o usiuario utilize somente execuntando o script, começa pelo main
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(_c("\n[!] Scan interrompido pelo usuário (Ctrl+C).", Fore.YELLOW, bright=True))
        sys.exit(0)
