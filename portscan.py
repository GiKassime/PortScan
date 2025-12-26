import sys
import socket
import time

try:
    from scapy.all import *
except ImportError:
    print("\n[!] Erro Crítico: A biblioteca 'scapy' não está instalada.")
    print("[-] Para corrigir, execute: pip install scapy")
    print("[-] Se estiver no Windows, instale também o Npcap: https://npcap.com/\n")
    sys.exit(1)



def main():
    # para executar o portscan precisa de um ip ou hostname + opcionalmente um argumento
    # uso esperado: python3 portscan.py <IP> [ -udp | -ack | -decoy ]
    if len(sys.argv) not in (2, 3):
        print("Uso: python3 portscan.py <IP> [-udp, -ack, -decoy]")
        sys.exit(1)
    #pega a primeira parte do comando que é o ip ou hostname
    input_usuario = sys.argv[1]

    # trtamento de dns e exceções
    try:
        ip_alvo = socket.gethostbyname(input_usuario)
        #ideintifica qual tipo de scan será executado
        scan = sys.argv[2]   
        #mais para a frente deixar a opção de escolher uma porta especifica, ou todas!
        max_porta = 1024
        match scan:
                case '-udp':
                    funcao = scan_udp
                case '-ack':
                    funcao = scan_ack
                case '-decoy':
                    funcao = scan_decoy
                case _:
                    print(f"Opção '{scan}' desconhecida. Usando padrão.")
                    percorre_portas(max_porta, scan_syn, ip_alvo)

        print(f"Iniciando scan com {scan} em {ip_alvo}")
        percorre_portas(max_porta, funcao, ip_alvo)


        
        # executar função scan 
        
    except socket.gaierror:
        # Erro de DNS 
        print(f"[!] Erro: Não foi possível resolver o hostname '{input_usuario}'. Verifique se está correto.")
        return
    except Exception as e:
        print(f"[!] Erro inesperado: {e}")


    
#função para scanear portas abertas 
def scan_syn(ip_alvo, porta):
    print(f"'{alvo}' : '{porta}' teste")


#função para descobrir serviços UDP
def scan_udp(alvo, porta):
    print(f"'{alvo}' : '{porta}' teste")

# função para mapear o Firewall
def scan_ack(alvo, porta):
    print(f"'{alvo}' : '{porta}' teste")



# função para envia pacotes com IPs falso para despistar o alvo
def scan_decoy(alvo, porta):
    print(f"'{alvo}' : '{porta}' teste")


def obter_servico(porta, protocolo):
    try:
        # descobrir o nome do protocolo
        nome = socket.getservbyport(porta, protocolo)
        return nome
    except:
        return "desconhecido"
    
def percorre_portas(max_porta, funcao_scan, ip_alvo):
    for porta in range(1, max_porta + 1):
        funcao_scan(ip_alvo, porta)
        time.sleep(0.1)  # evita sobrecarga na rede
        
# garante que o script só rode se for executado diretamente
if __name__ == "__main__":
    main()