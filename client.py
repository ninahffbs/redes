#!/usr/bin/env python3
import socket
import time
import random
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 5000

PAYLOAD_MAX = 4 #dados por fragmento
SEQ_START = 0
TIMEOUT = 3.0 
MAX_SEQ = 256 

LOSS_RATE = 0.1 

DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
DH_G = 2

def recv_until(sock, delimiter=b'\n'):
    buffer = b''
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                return None
            buffer += data
            if delimiter in buffer:
                msg_raw, buffer = buffer.split(delimiter, 1)
                return msg_raw.decode()
        except socket.timeout:
            raise
        except Exception:
            return None

def checksum_of(data: bytes) -> int:
    return sum(data) % 256

def aes_encrypt_to_b64(plaintext_bytes: bytes, key: bytes) -> str:
    #criptografa a mensagem usando AES, adiciona vetor de inicializacao e codifica em base64.
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    out = iv + ct
    #retorna o resultado codificado em base64
    return base64.b64encode(out).decode()

def make_packet(seq: int, payload: str, corrupt: bool = False) -> str:
    length = len(payload)
    chk = checksum_of(payload.encode())
    if corrupt:
        chk = (chk + 1) % 256 #força checksum errado
        print(f"!!! [ERRO SIMULADO] Checksum corrompido para seq={seq % MAX_SEQ} (global={seq})")
    return f"{seq}|{length}|{chk}|{payload}\n"

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Erro: Não foi possível conectar ao servidor. Verifique se o servidor está rodando.")
        return

    modo = input("Modo de operação (GBN ou SR): ").strip().upper() or "GBN"
    while modo not in ('GBN', 'SR'):
        print("Modo inválido. Use 'GBN' ou 'SR'.")
        modo = input("Modo de operação (GBN ou SR): ").strip().upper() or "GBN"

    while True:
        tamanho_maximo = input("Tamanho máximo da mensagem por envio (>=30): ").strip()
        if not tamanho_maximo:
            tamanho_maximo = "2048"
            break
        try:
            tm = int(tamanho_maximo)
            if tm < 30:
                print("Tamanho mínimo é 30. Tente novamente.")
                continue
            break
        except:
            print("Digite um número válido.")
            continue

    simular_erro = input("Simular erro determinístico no primeiro pacote? (s/n): ").strip().lower() == 's'

    handshake = f"{modo};{tamanho_maximo}"
    client_socket.sendall(handshake.encode())

    resposta = recv_until(client_socket)
    if resposta is None:
        print("Erro no handshake: Servidor fechou a conexão.")
        client_socket.close()
        return

    print("Resposta do servidor (handshake):", resposta)
    window_size = 5
    server_dh = None
    try:
        #extrai o tamanho da janela e a chave publica dh do servidor da resposta
        parts = resposta.split(';')
        for p in parts:
            if p.startswith("janela="):
                window_size = int(p.split('=',1)[1])
            if p.startswith("dh="):
                server_dh = int(p.split('=',1)[1])
    except:
        pass

    if server_dh is None:
        print("Servidor não enviou parâmetro DH. Abortando.")
        client_socket.close()
        return
    #gera a chave privada dh do cliente
    client_priv = int.from_bytes(get_random_bytes(64), 'big') % (DH_PRIME - 2) + 2
    #calcula a chave publica dh do cliente
    client_pub = pow(DH_G, client_priv, DH_PRIME)
    #calcula o segredo compartilhado
    shared = pow(server_dh, client_priv, DH_PRIME)
    #deriva a chave AES a partir do hash SHA256 do segredo compartilhado
    aes_key = hashlib.sha256(str(shared).encode()).digest()
    #envia a chave publica do cliente ao servidor
    client_socket.sendall(f"DH|{client_pub}\n".encode())
    print("DH concluído — chave simétrica derivada (AES-256).")

    print(f"Janela determinada pelo servidor: {window_size}")

    while True:
        message = input("Digite a mensagem a enviar (ou vazio para uma mensagem padrão): ")
        if not message:
            message = "Olá mundo! Esta é uma mensagem de teste para transmissão segmentada."
        if len(message) > int(tamanho_maximo):
            print(f"Mensagem maior que tamanho máximo ({tamanho_maximo}). Digite menor.")
            continue
        break
    
    #criptografa a mensagem completa e obtem a string base64
    ciphertext_b64 = aes_encrypt_to_b64(message.encode(), aes_key)
    #fragmenta a string base64 em fragmentos
    fragments = [ciphertext_b64[i:i+PAYLOAD_MAX] for i in range(0, len(ciphertext_b64), PAYLOAD_MAX)]
    total_fragments = len(fragments)
    print(f"Mensagem original {len(message)} chars -> ciphertext base64 {len(ciphertext_b64)} chars -> {total_fragments} fragmentos de até {PAYLOAD_MAX} chars.")

    #pacote mais antigo não reconhecido
    base_seq = SEQ_START
    next_seq_to_send = SEQ_START #proximo número de sequencia a ser enviado
    window_packets = {} #armazenar pacotes enviados dentro da janela
    client_socket.settimeout(TIMEOUT)

    send_times = {} #armazena o tempo de envio de cada pacote (implementado para o SR)
    simular_erro_ativo = simular_erro

    if modo == 'GBN':
        timer = None
        while base_seq < total_fragments: #loop ate que todos os fragmentos tenham sido reconhecidos
            while next_seq_to_send < total_fragments and (next_seq_to_send - base_seq) < window_size:
                payload = fragments[next_seq_to_send]
                #simulacao da corrupcao so no primeiro pacote (SEQ_START) se ativada
                corrupt = simular_erro_ativo and next_seq_to_send == SEQ_START
                pkt = make_packet(next_seq_to_send, payload, corrupt)
                if corrupt:
                    simular_erro_ativo = False
                    print("-> Simulação de erro determinístico desativada para retransmissões.")

                #simulacao de perda de pacote
                if random.random() < LOSS_RATE:
                    print(f"!!! [PERDA SIMULADA] Pacote seq={next_seq_to_send}")
                else:
                    client_socket.sendall(pkt.encode())
                    #armazena pacote enviado (caso precise de retransmissao)
                    window_packets[next_seq_to_send] = (pkt, payload)
                    print(f"[ENVIADO] seq={next_seq_to_send % MAX_SEQ} (Global={next_seq_to_send}) len={len(payload)} chk={checksum_of(payload.encode())} payload(b64)='{payload}'")

                if timer is None and next_seq_to_send == base_seq:
                    timer = time.time()
                    print(f"-> Timer iniciado para base_seq={base_seq}")

                next_seq_to_send += 1
                time.sleep(0.02)

            try:
                if timer is not None and (time.time() - timer) > TIMEOUT:
                    raise socket.timeout

                msg = recv_until(client_socket)
                if msg is None:
                    print("Conexão fechada pelo servidor.")
                    break

                if msg.startswith("ACK|"):
                    parts = msg.split('|')
                    try:
                        ack_seq_expected = int(parts[1])
                    except:
                        print("ACK inválido recebido. Ignorando.")
                        continue

                    print(f"[ACK RECEBIDO] ack_seq={ack_seq_expected}")

                    if ack_seq_expected > base_seq:
                        for seq in range(base_seq, ack_seq_expected):
                            window_packets.pop(seq, None)
                        base_seq = ack_seq_expected
                        print(f"-> Base atualizada para {base_seq}. Timer resetado.")
                        if base_seq < next_seq_to_send:
                            timer = time.time()
                        else:
                            timer = None #todos os pacotes na janela atual foram reconhecidos

                elif msg.startswith("NAK|"):
                    parts = msg.split('|')
                    try:
                        nak_seq = int(parts[1])
                    except:
                        nak_seq = -1
                    #NAK -> retransmissao total a partir da base
                    print(f"[NAK RECEBIDO] NAK para seq={nak_seq}. Forçando Timeout para retransmissão GBN.")
                    raise socket.timeout #força 'except socket.timeout'

                elif msg == "ACK_END":
                    print("[SERVER] confirmou encerramento (ACK_END recebido durante a transmissão)")
                    break
                else:
                    print("[RECEBIDO] (mensagem não reconhecida):", msg)

            except socket.timeout:
                print(f"!!! [TIMEOUT] Timer expirou. Retransmitindo (Go-Back-N) a partir de base_seq={base_seq}.")
                timer = time.time()
                #retransmissao a partir da base
                next_seq_to_send = base_seq
                window_packets.clear()

            except Exception as e:
                print(f"Erro inesperado: {e}. Interrompendo transmissão.")
                break

    else:
        #SR
        acked = set()
        send_times = {} #timer individual para cada pacote enviado

        while base_seq < total_fragments:
            while next_seq_to_send < total_fragments and (next_seq_to_send - base_seq) < window_size:
                payload = fragments[next_seq_to_send]
                corrupt = simular_erro_ativo and next_seq_to_send == SEQ_START
                pkt = make_packet(next_seq_to_send, payload, corrupt)

                if corrupt:
                    simular_erro_ativo = False
                    print("-> Simulação de erro determinístico desativada para retransmissões.")

                # always register packet and timer even if loss simulated
                window_packets[next_seq_to_send] = (pkt, payload)
                send_times[next_seq_to_send] = time.time()

                if random.random() < LOSS_RATE:
                    print(f"!!! [PERDA SIMULADA] Pacote seq={next_seq_to_send} (não enviado)")
                else:
                    client_socket.sendall(pkt.encode())
                    print(f"[ENVIADO] seq={next_seq_to_send % MAX_SEQ} (Global={next_seq_to_send}) len={len(payload)} chk={checksum_of(payload.encode())} payload(b64)='{payload}'")

                next_seq_to_send += 1
                time.sleep(0.02)

            # check SR timeouts and retransmit as needed
            now = time.time()
            to_retransmit = []
            #loop sobre os timers ativos -> pacotes enviados e nao reconhecidos
            for seq, t0 in list(send_times.items()):
                if seq in acked:
                    continue
                if (now - t0) > TIMEOUT:
                    to_retransmit.append(seq) #marca para retransmissao

            for seq in to_retransmit:
                pkt, payload = window_packets.get(seq, (None, None))
                if pkt is None:
                    send_times.pop(seq, None)
                    continue
                # regenera o pacote na retransmissao (correcao de bug)
                pkt = make_packet(seq, payload, corrupt=False)
                window_packets[seq] = (pkt, payload)
                print(f"!!! [TIMEOUT SR] Retransmitindo seq={seq}")
                if random.random() < LOSS_RATE:
                    print(f"!!! [PERDA SIMULADA] (na retransmissão) seq={seq}")
                else:
                    client_socket.sendall(pkt.encode())
                send_times[seq] = time.time()

            try:
                client_socket.settimeout(0.5)
                msg = recv_until(client_socket)
                client_socket.settimeout(TIMEOUT)
                if msg is None:
                    print("Conexão fechada pelo servidor.")
                    break

                if msg.startswith("ACK_IND|"):
                    parts = msg.split('|')
                    try:
                        ack_seq = int(parts[1])
                    except:
                        print("ACK_IND inválido, ignorando.")
                        continue
                    print(f"[ACK_IND RECEBIDO] seq={ack_seq}")
                    acked.add(ack_seq)
                    window_packets.pop(ack_seq, None)
                    send_times.pop(ack_seq, None)
                    while base_seq in acked:
                        base_seq += 1

                elif msg.startswith("ACK|"):
                    parts = msg.split('|')
                    try:
                        ack_expected = int(parts[1])
                    except:
                        continue
                    print(f"[ACK (cumulativo) recebido] ack_expected={ack_expected}")
                    for seq in range(base_seq, ack_expected):
                        acked.add(seq)
                        window_packets.pop(seq, None)
                        send_times.pop(seq, None)
                    base_seq = ack_expected

                elif msg.startswith("NAK|"):
                    parts = msg.split('|')
                    try:
                        nak_seq = int(parts[1])
                    except:
                        nak_seq = -1
                    print(f"[NAK RECEBIDO] nak_seq={nak_seq}")
                    if nak_seq >= 0 and nak_seq in window_packets:
                        #retransmite so o pacote com erro
                        #correcao de bug
                        pkt, payload = window_packets[nak_seq]
                        pkt = make_packet(nak_seq, payload, corrupt=False)
                        window_packets[nak_seq] = (pkt, payload)
                        print(f"-> SR: retransmitindo seq={nak_seq} por causa de NAK (checksum corrigido)")
                        if random.random() < LOSS_RATE:
                            print(f"!!! [PERDA SIMULADA] (na retransmissão NAK) seq={nak_seq}")
                        else:
                            client_socket.sendall(pkt.encode())
                        send_times[nak_seq] = time.time()
                    else:
                        print("-> NAK inválido ou fora da janela. Ignorando.")

                elif msg == "ACK_END":
                    print("Servidor confirmou encerramento (ACK_END).")
                    break
                else:
                    print("[RECEBIDO] (não reconhecido):", msg)

            except socket.timeout:
                pass
            except Exception as e:
                print("Erro ao receber:", e)
                break

    try:
        #fim dos fragmentos
        client_socket.sendall("END\n".encode())
        final_ack = recv_until(client_socket)
        if final_ack == "ACK_END":
            print("Servidor confirmou encerramento da transmissão.")
        else:
            if final_ack:
                print("Resposta inesperada no encerramento:", final_ack)
    except Exception:
        pass

    client_socket.close()
    print("Cliente finalizado.")

if __name__ == "__main__":
    main()
