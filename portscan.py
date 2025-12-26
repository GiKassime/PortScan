import sys

try:
    from scapy.all import *
except ImportError:
    print("\n[!] Erro Crítico: A biblioteca 'scapy' não está instalada.")
    print("[-] Para corrigir, execute: pip install scapy")
    print("[-] Se estiver no Windows, instale também o Npcap: https://npcap.com/\n")
    sys.exit(1)

import argparse
import socket

def main():
    # config do parser - o interpretador de comandos
    parser = argparse.ArgumentParser(description="PortScan Básico com Scapy")
    
    # add  o argumento esperado. 
    parser.add_argument("alvo", help="IP ou Hostname alvo (ex: 192.168.0.1 ou scanme.nmap.org)")
    
    # ler oq usuario digitou
    args = parser.parse_args()
    input_usuario = args.alvo

    # trtamento de dns e exceções
    try:
        ip_alvo = socket.gethostbyname(input_usuario)
        print(f"[*] Iniciando scan em: {input_usuario} ({ip_alvo})")
        
        # executar função sacan 
        
    except socket.gaierror:
        # Erro de DNS (Get Address Info Error)
        print(f"[!] Erro: Não foi possível resolver o hostname '{input_usuario}'. Verifique se está correto.")
        return
    except Exception as e:
        print(f"[!] Erro inesperado: {e}")

# garante que o script só rode se for executado diretamente
if __name__ == "__main__":
    main()
    
#função para scanear portas abertas 
def scan_syn(ip_alvo, porta):
#função para descobrir serviços UDP
def scan_udp(alvo, porta):

# função para mapear o Firewall
def scan_ack(alvo, porta):

# função para envia pacotes com IPs falso para despistar o alvo
def scan_decoy(alvo, porta):
    

def obter_servico(porta, protocolo):
    try:
        # descobrir o nome do protocolo
        nome = socket.getservbyport(porta, protocolo)
        return nome
    except:
        return "desconhecido"