import sys
import socket
import time
import signal
import threading
try:
    from scapy.all import *
except ImportError:
    print("\n[!] Erro Crítico: A biblioteca 'scapy' não está instalada.")
    print("[-] Para corrigir, execute: pip install scapy")
    print("[-] Se estiver no Windows, instale também o Npcap: https://npcap.com/\n")
    sys.exit(1)

detecta_parada = threading.Event()

# Handler para sinais (Ctrl+C -> SIGINT, SIGTERM). Apenas sinaliza o Event
def _handle_signal(signum, frame):
    detecta_parada.set()

signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

def main():
    # para executar o portscan precisa de um ip ou hostname + opcionalmente um argumento
    if len(sys.argv) < 2:
        print("Digite python3 portscan.py -help para ajuda.")
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
        funcao = scan_syn
        scan_nome = 'SYN Scan (Padrão)'

        # Parse simples dos argumentos adicionais
        args = sys.argv[2:]
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ('-udp', '-ack', '-decoy'):
                if arg == '-udp':
                    funcao = scan_udp
                    scan_nome = 'UDP Scan'
                elif arg == '-ack':
                    funcao = scan_ack
                    scan_nome = 'ACK Scan'
                elif arg == '-decoy':
                    funcao = scan_decoy
                    scan_nome = 'Decoy Scan'
                i += 1
                continue

            if arg == '-p':
                # precisa ter o próximo valor
                if i + 1 >= len(args):
                    print("[!] Erro: faltou o valor após -p. Exemplo: -p 80-1024 ou -p 22")
                    sys.exit(1)
                valor = args[i + 1]
                try:
                    if '-' in valor:
                        partes = valor.split('-')
                        if len(partes) != 2:
                            raise ValueError('Formato inválido do intervalo de portas.')
                        a = int(partes[0])
                        b = int(partes[1])
                        # normaliza ordem
                        inicio_porta = max(1, min(a, b))
                        fim_porta = min(65535, max(a, b))
                    else:
                        p = int(valor)
                        if p < 1 or p > 65535:
                            raise ValueError('Porta fora do intervalo 1-65535.')
                        inicio_porta = p
                        fim_porta = p
                except ValueError as ve:
                    print(f"[!] Erro no argumento -p: {ve}")
                    sys.exit(1)
                i += 2
                continue

            # argumento desconhecido, apenas ignora de forma simples
            i += 1

        print(f"Iniciando scan {scan_nome} em {ip_alvo} | Portas: {inicio_porta}-{fim_porta}")
        percorre_portas(inicio_porta, fim_porta, funcao, ip_alvo)


        
        # executar função scan 
        
    except socket.gaierror:
        # Erro de DNS 
        print(f"[!] Erro: Não foi possível resolver o hostname '{input_usuario}'. Verifique se está correto.")
        return
    except Exception as e:
        print(f"[!] Erro inesperado: {e}")


def enviar_pacote(ip_alvo, porta, flags, protocolo='tcp'):
    if protocolo == 'tcp':
        pacote = IP(dst=ip_alvo)/TCP(dport=porta, flags=flags)
    else:  # udp
        pacote = IP(dst=ip_alvo)/UDP(dport=porta)
    
    # Enviar pacote e esperar resposta (timeout de 1 segundo)
    resposta = sr1(pacote, timeout=1, verbose=0)
    return resposta

    
#função para scanear portas abertas 
def scan_syn(ip_alvo, porta):
    # Enviar pacote SYN
    resposta = enviar_pacote(ip_alvo, porta, 'S')
    
    # Analisar resposta
    if resposta is None:
        # Sem resposta - porta filtrada ou não respondeu
        return
    
    if resposta.haslayer(TCP):
        if resposta[TCP].flags == 0x12:  # SYN-ACK (porta aberta)
            # Enviar RST para fechar a conexão
            enviar_pacote(ip_alvo, porta, 'R')
            
            # Obter e exibir serviço
            servico = obter_servico(porta, 'tcp')
            print(f"[+] Porta {porta}/tcp aberta - Serviço: {servico}")
        elif resposta[TCP].flags == 0x14:  # RST-ACK (porta fechada)
            # Porta fechada - não exibe nada
            pass


#função para descobrir serviços UDP
def scan_udp(ip_alvo, porta):
    # Envia um pacote UDP simples (sem payload) e aguarda resposta
    resposta = enviar_pacote(ip_alvo, porta, flags='', protocolo='udp')

    # Sem resposta: pode ser aberta/filtrada, não imprime (consistente com SYN)
    if resposta is None:
        return

    # Se houve resposta UDP, a porta está aberta
    if resposta.haslayer(UDP):
        servico = obter_servico(porta, 'udp')
        print(f"[+] Porta {porta}/udp aberta - Serviço: {servico}")
        return

    # Se veio ICMP tipo 3 código 3 (port unreachable), porta fechada
    if resposta.haslayer(ICMP):
        icmp = resposta[ICMP]
        # type 3 = Destination Unreachable; code 3 = Port Unreachable
        if int(icmp.type) == 3 and int(icmp.code) == 3:
            # Porta fechada - não exibe nada
            return
        # Outros códigos podem indicar filtragem - manter silêncio para simplicidade
        return

# função para mapear o Firewall
# ACK scan: não detecta aberto/fechado, apenas filtrado vs não filtrado
# Regra simples:
# - Resposta TCP com RST/RST-ACK => não filtrado
# - Sem resposta ou ICMP dest-unreach (códigos de filtragem) => filtrado
# Imprime somente quando filtrado

def scan_ack(ip_alvo, porta):
    resposta = enviar_pacote(ip_alvo, porta, 'A')

    # Sem resposta: provavelmente filtrado por firewall
    if resposta is None:
        print(f"[!] Porta {porta}/tcp filtrada (sem resposta)")
        return

    # RST ou RST-ACK indica que o pacote chegou (não filtrado)
    if resposta.haslayer(TCP):
        flags = int(resposta[TCP].flags)
        if flags in (0x04, 0x14):  # RST (0x04) ou RST-ACK (0x14)
            return  # não filtrado, não imprime

    # ICMP Destination Unreachable com códigos de filtragem => filtrado
    if resposta.haslayer(ICMP):
        icmp = resposta[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 3, 9, 10, 13):
            print(f"[!] Porta {porta}/tcp filtrada (ICMP code {int(icmp.code)})")
            return

    # Qualquer outra coisa: manter silêncio para simplicidade
    return



# função para envia pacotes com IPs falso para despistar o alvo
def gerar_ip_falso():
    """Gera um IP aleatório para usar como decoy"""
    import random
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def scan_decoy(ip_alvo, porta):
    """
    Decoy scan: envia pacotes SYN com IPs falsos para despistar logs do alvo
    Intercala pacotes decoy com o pacote real para dificultar rastreamento
    """
    import random
    
    # Gera 2-3 IPs decoy aleatórios
    ips_decoy = [gerar_ip_falso() for _ in range(random.randint(2, 3))]
    
    # Envia SYN decoy (sem esperar resposta) - serve só para despistar
    for ip_falso in ips_decoy:
        pacote_decoy = IP(src=ip_falso, dst=ip_alvo)/TCP(dport=porta, flags='S')
        send(pacote_decoy, verbose=0)
        time.sleep(0.05)
    
    # Envia SYN real e aguarda resposta normalmente
    resposta = enviar_pacote(ip_alvo, porta, 'S')
    
    # Análise idêntica ao scan_syn
    if resposta is None:
        return
    
    if resposta.haslayer(TCP):
        if resposta[TCP].flags == 0x12:  # SYN-ACK (porta aberta)
            enviar_pacote(ip_alvo, porta, 'R')
            servico = obter_servico(porta, 'tcp')
            print(f"[+] Porta {porta}/tcp aberta - Serviço: {servico} (com decoys)")
        elif resposta[TCP].flags == 0x14:  # RST-ACK (porta fechada)
            pass


def obter_servico(porta, protocolo):
    try:
        # descobrir o nome do protocolo
        nome = socket.getservbyport(porta, protocolo)
        return nome
    except:
        return "desconhecido"
    
def percorre_portas(inicio_porta, fim_porta, funcao_scan, ip_alvo):
    for porta in range(inicio_porta, fim_porta + 1):
        if detecta_parada.is_set():
            parar()
        funcao_scan(ip_alvo, porta)
        time.sleep(0.1)  # evita sobrecarga na rede
        
def menu_help():
    print("Uso: python3 portscan.py <IP> [-udp, -ack, -decoy] [-p <porta|inicio-fim>]")
    print("Opções:")
    print("  -udp     Realiza um scan UDP")
    print("  -ack     Realiza um scan ACK")
    print("  -decoy   Realiza um scan com IPs falsos para despistar o alvo")
    print("  -p       Especifique uma porta única (ex: 22) ou intervalo (ex: 1-1024). Padrão: 1-1024")
    print("Se nenhuma opção for fornecida, será realizado um SYN Scan padrão.")

def parar():
    print("\n[!] Scan interrompido pelo usuário.")
    sys.exit(0)
# garante que o script só rode se for executado diretamente
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Caso um KeyboardInterrupt ocorra (por exemplo em algumas situações),
        # garante parada limpa através do Event e sai sem traceback.
        detecta_parada.set()
        print("\n[!] KeyboardInterrupt — encerrando.")
        sys.exit(0)