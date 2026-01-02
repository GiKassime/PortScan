import sys
import socket
import time
import random
try:
    from scapy.all import *
except ImportError:
    print("\nA biblioteca 'scapy' não está instalada.")
    print("[-] Para corrigir, execute: pip install scapy")
    print("[-] Se estiver no Windows, instale também o Npcap: https://npcap.com/\n")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)  # Reseta cores automaticamente
    CORES_DISPONIVEIS = True
except ImportError:
    # Se colorama não estiver instalado, define cores vazias
    class Fore:
        GREEN = RED = YELLOW = CYAN = BLUE = MAGENTA = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''
    CORES_DISPONIVEIS = False

TIPOS_SCAN = {
    '-syn': ('syn', 'SYN Scan'),
    '-udp': ('udp', 'UDP Scan'),
    '-ack': ('ack', 'ACK Scan')
}

def main():
    # espera plmns 2 argumentos que é o nome do scr e o hostname/ip
    if len(sys.argv) < 2:
        print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro: Nenhum argumento fornecido!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[?] Digite: python3 portscan.py -help para ajuda.{Style.RESET_ALL}")
        sys.exit(1)
    #pega a primeira parte do comando que é o ip ou hostname
    input_usuario = sys.argv[1]
    
    # se oediu ajuda:
    if input_usuario == '-help':
        menu_help()
        sys.exit(0)

    # trtamento de dns e exceções
    try:
        ip_alvo = socket.gethostbyname(input_usuario)

        # Valores padrão
        inicio_porta = 1
        fim_porta = 1024
        lista_portas = None  # Para portas separadas por vírgula
        tipo_scan = 'syn' 
        usar_decoy = False
        qtd_decoy = 2  # Quantidade padrão de IPs decoy
        scan_nome = 'SYN Scan (Padrão)'

        # Argumentos adicionais
        args = sys.argv[2:]
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg in TIPOS_SCAN:
                tipo_scan, scan_nome = TIPOS_SCAN[arg]
                i += 1
                continue
            
            # Modificador decoy
            if arg == '-decoy':
                if usar_decoy:
                    print(f"{Fore.YELLOW}[!] Aviso: -decoy já foi especificado, ignorando duplicada.{Style.RESET_ALL}")
                    i += 1
                    continue
                usar_decoy = True
                # Verifica se tem um número após -decoy
                if i + 1 < len(args) and args[i + 1].isdigit():
                    qtd_decoy = int(args[i + 1])  # Define quantidade de IPs decoy
                    i += 2
                else:
                    i += 1
                continue

            if arg == '-p':
                # precisa ter o próximo valor
                if i + 1 >= len(args):
                    print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro: faltou o valor após -p!{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[?] Exemplos: -p 80 | -p 80-443 | -p 80,443,22{Style.RESET_ALL}")
                    sys.exit(1)
                valor = args[i + 1]
                try:
                    tipo_porta, dados_porta = validar_portas(valor)
                    if tipo_porta == 'lista':
                        # Lista de portas separadas por vírgula
                        lista_portas = dados_porta
                    elif tipo_porta == 'intervalo':
                        # Intervalo de portas
                        inicio_porta, fim_porta = dados_porta
                        lista_portas = None
                    else:  # 'unica'
                        # Porta única
                        inicio_porta = fim_porta = dados_porta
                        lista_portas = None
                except ValueError as ve:
                    print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro no argumento -p: {ve}{Style.RESET_ALL}")
                    sys.exit(1)
                i += 2
                continue

            # argumento desconhecido
            if arg.startswith('-'):
                print(f"{Fore.YELLOW}[!] Aviso: argumento desconhecido '{arg}' será ignorado.{Style.RESET_ALL}")
            i += 1

        # Atualizar nome do scan se usar decoy
        if usar_decoy:
            scan_nome += ' com Decoy'
        
        # Formatar exibição de portas
        if lista_portas:
            portas_str = ','.join(map(str, lista_portas))
        else:
            portas_str = f"{inicio_porta}-{fim_porta}"
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] Iniciando {scan_nome} em {Fore.GREEN}{ip_alvo}{Fore.CYAN} | Portas: {Fore.YELLOW}{portas_str}{Style.RESET_ALL}\n")
        percorre_portas(inicio_porta, fim_porta, tipo_scan, ip_alvo, usar_decoy, qtd_decoy, lista_portas)
                
    except socket.gaierror:
        # Erro de DNS 
        print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro de DNS: Não foi possível resolver '{input_usuario}'{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Verifique se o IP/hostname está correto.{Style.RESET_ALL}")
        return
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[⚠] Scan interrompido pelo usuário.{Style.RESET_ALL}")
        return
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}[✗] Erro inesperado: {e}{Style.RESET_ALL}")
        return


def percorre_portas(inicio_porta, fim_porta, tipo_scan, ip_alvo, usar_decoy=False, qtd_decoy=2, lista_portas=None):
    SCANS = {'syn': scan_syn, 'udp': scan_udp, 'ack': scan_ack}
    funcao_scan = SCANS.get(tipo_scan, scan_syn)  
    
    # Se tem lista de portas específicas, usa ela
    if lista_portas:
        for porta in lista_portas:
            funcao_scan(ip_alvo, porta, usar_decoy, qtd_decoy)
            time.sleep(0.1)
    else:
        # Senão, usa intervalo
        for porta in range(inicio_porta, fim_porta + 1):
            funcao_scan(ip_alvo, porta, usar_decoy, qtd_decoy)
            time.sleep(0.1) 
        

# Funções de scan
def scan_syn(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    # Envia pacotes decoy antes do scan real
    if usar_decoy:
        enviar_pacotes_decoy(ip_alvo, porta, qtd_decoy=qtd_decoy)
        time.sleep(1)  # Aguarda depois dos decoys
    
    # Envia pacote SYN para verificar se a porta está aberta
    resposta = enviar_pacote(ip_alvo, porta, 'S')
    if resposta is None:  # Nenhuma resposta 
        return
    
    # Se receber SYN-ACK (0x12), a porta está aberta
    if resposta.haslayer(TCP) and resposta[TCP].flags == 0x12:
        enviar_pacote(ip_alvo, porta, 'R')  # Envia RST para fechar a conexão
        servico = obter_servico(porta, 'tcp')  # Descobre o nome do serviço
        modo = formatar_modo_decoy(usar_decoy)  # Adiciona "(decoy)" se necessário
        print(f"{Fore.GREEN}[+] Porta {porta}/tcp aberta - Serviço: {servico}{modo}{Style.RESET_ALL}")

def scan_udp(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    if usar_decoy:
        enviar_pacotes_decoy(ip_alvo, porta, protocolo='udp', qtd_decoy=qtd_decoy)
    
    # Envia pacote UDP para verificar a porta
    resposta = enviar_pacote(ip_alvo, porta, flags='', protocolo='udp')
    if resposta is None:  # Sem resposta = porta pode estar aberta ou filtrada
        servico = obter_servico(porta, 'udp')
        modo = formatar_modo_decoy(usar_decoy)
        print(f"{Fore.CYAN}[?] Porta {porta}/udp aberta|filtrada - Serviço: {servico}{modo}{Style.RESET_ALL}")
        return

    # Se receber resposta UDP, porta está aberta
    if resposta.haslayer(UDP):
        servico = obter_servico(porta, 'udp')
        modo = formatar_modo_decoy(usar_decoy)
        print(f"{Fore.GREEN}[+] Porta {porta}/udp aberta - Serviço: {servico}{modo}{Style.RESET_ALL}")
        return

    # Se receber ICMP code 3,3 (porta fechada), ignora
    if resposta.haslayer(ICMP):
        icmp = resposta[ICMP]  # Extrai a camada ICMP
        if int(icmp.type) == 3 and int(icmp.code) == 3:  # Destination Unreachable
            return

def scan_ack(ip_alvo, porta, usar_decoy=False, qtd_decoy=2):
    if usar_decoy:
        enviar_pacotes_decoy(ip_alvo, porta, flags='A', qtd_decoy=qtd_decoy)
    
    resposta = enviar_pacote(ip_alvo, porta, 'A')
    modo = formatar_modo_decoy(usar_decoy)
    
    if resposta is None:
        print(f"{Fore.YELLOW}[!] Porta {porta}/tcp filtrada (sem resposta){modo}{Style.RESET_ALL}")
        return

    if resposta.haslayer(TCP):
        flags = int(resposta[TCP].flags)
        if flags in (0x04, 0x14):  # RST ou RST-ACK = porta aberta/não filtrada
            print(f"{Fore.CYAN}[?] Porta {porta}/tcp não-filtrada (respondeu RST){modo}{Style.RESET_ALL}")
            return

    if resposta.haslayer(ICMP):
        icmp = resposta[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 3, 9, 10, 13):
            print(f"{Fore.YELLOW}[!] Porta {porta}/tcp filtrada (ICMP code {int(icmp.code)}){Style.RESET_ALL}")
            return
    
def enviar_pacote(ip_alvo, porta, flags, protocolo='tcp'):
    # Monta pacote TCP ou UDP com IP de destino
    if protocolo == 'tcp':
        pacote = IP(dst=ip_alvo)/TCP(dport=porta, flags=flags)  # Pacote TCP com flags (ex: SYN, ACK, RST)
    else:  # udp
        pacote = IP(dst=ip_alvo)/UDP(dport=porta)  # Pacote UDP simples
    
    resposta = sr1(pacote, timeout=10, verbose=0)
    return resposta

def enviar_pacotes_decoy(ip_alvo, porta, flags='S', protocolo='tcp', qtd_decoy=2):
    ips_decoy = [gerar_ip_falso() for _ in range(qtd_decoy)]
    
   
    for ip_falso in ips_decoy:
        if protocolo == 'tcp':
            pacote_decoy = IP(src=ip_falso, dst=ip_alvo)/TCP(dport=porta, flags=flags)  # Pacote TCP falso
        else:
            pacote_decoy = IP(src=ip_falso, dst=ip_alvo)/UDP(dport=porta)  # Pacote UDP falso
        send(pacote_decoy, verbose=0) 
        time.sleep(0.05) 


def validar_portas(valor):
    # Verifica se são múltiplas portas separadas por vírgula (ex: 80,443,22)
    if ',' in valor:
        portas = valor.split(',')  # Separa as portas
        portas_validadas = []
        for porta_str in portas:
            porta_str = porta_str.strip()  # Remove espaços
            try:
                p = int(porta_str)
            except ValueError:
                raise ValueError(f"'{porta_str}' não é um número válido")
            
            if p < 1 or p > 65535:
                raise ValueError(f'Porta {p} deve estar entre 1 e 65535')
            portas_validadas.append(p)
        
        # Retorna lista de portas
        return 'lista', portas_validadas
    
    # Verifica se é um intervalo de portas (ex: 80-443)
    elif '-' in valor:
        partes = valor.split('-')  # Separa início e fim
        if len(partes) != 2:
            raise ValueError('Use o formato: inicio-fim (ex: 80-443)')
        try:
            a, b = int(partes[0]), int(partes[1])  # Converte para inteiros
        except ValueError:
            raise ValueError(f"'{valor}' não contém números válidos")
        
        # Valida se as portas estão no intervalo permitido (1-65535)
        if a < 1 or a > 65535 or b < 1 or b > 65535:
            raise ValueError('Portas devem estar entre 1 e 65535')
        
        return 'intervalo', (min(a, b), max(a, b))  # Retorna em ordem (menor, maior)
    else:
        # Valida porta única
        try:
            p = int(valor)  # Converte para inteiro
        except ValueError:
            raise ValueError(f"'{valor}' não é um número inteiro válido")
        
        if p < 1 or p > 65535:
            raise ValueError('Porta deve estar entre 1 e 65535')
        
        return 'unica', p  # Retorna a mesma porta

def formatar_modo_decoy(usar_decoy):
    return f" {Fore.MAGENTA}(decoy){Style.RESET_ALL}" if usar_decoy else ""

def gerar_ip_falso():
    # Gera um IP aleatório para usar no decoy scan
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def obter_servico(porta, protocolo):
    # Tenta descobrir o nome do serviço usando a porta (ex: 80 = http, 22 = ssh)
    try:
        return socket.getservbyport(porta, protocolo)
    except:
        return "desconhecido"  # Se não souber, retorna desconhecido

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