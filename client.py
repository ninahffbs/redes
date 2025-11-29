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

PAYLOAD_MAX = 4
SEQ_START = 0
TIMEOUT = 3.0     # segundos
MAX_SEQ = 256     # para apresentação cíclica

# Simulação
LOSS_RATE = 0.1   # perda aleatória (ajuste para 0.0 se quiser sem perdas)

# --- Diffie-Hellman params (must match server) ---
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
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    out = iv + ct
    return base64.b64encode(out).decode()

def make_packet(seq: int, payload: str, corrupt: bool = False) -> str:
    # payload is ASCII text (base64 ciphertext) at this stage
    length = len(payload)
    chk = checksum_of(payload.encode())
    if corrupt:
        chk = (chk + 1) % 256
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

    # Envia handshake (mode;tamanho)
    handshake = f"{modo};{tamanho_maximo}"
    client_socket.sendall(handshake.encode())

    # Recebe ACK com server_pub (dh)
    resposta = recv_until(client_socket)
    if resposta is None:
        print("Erro no handshake: Servidor fechou a conexão.")
        client_socket.close()
        return

    print("Resposta do servidor (handshake):", resposta)
    window_size = 5
    server_dh = None
    try:
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

    # Generate client DH and send
    client_priv = int.from_bytes(get_random_bytes(64), 'big') % (DH_PRIME - 2) + 2
    client_pub = pow(DH_G, client_priv, DH_PRIME)
    # compute shared secret
    shared = pow(server_dh, client_priv, DH_PRIME)
    aes_key = hashlib.sha256(str(shared).encode()).digest()  # 32 bytes AES-256
    # send client pub to server
    client_socket.sendall(f"DH|{client_pub}\n".encode())
    print("DH concluído — chave simétrica derivada (AES-256).")

    print(f"Janela determinada pelo servidor: {window_size}")

    # Mensagem plain text (will be encrypted)
    while True:
        message = input("Digite a mensagem a enviar (ou vazio para 'Olá mundo!'): ")
        if not message:
            message = "Olá mundo! Esta é uma mensagem de teste para transmissão segmentada."
        if len(message) > int(tamanho_maximo):
            print(f"Mensagem maior que tamanho máximo ({tamanho_maximo}). Digite menor.")
            continue
        break

    # Encrypt whole plaintext first, base64-encode ciphertext
    ciphertext_b64 = aes_encrypt_to_b64(message.encode(), aes_key)
    # Now fragment the base64 ciphertext into PAYLOAD_MAX chars chunks
    fragments = [ciphertext_b64[i:i+PAYLOAD_MAX] for i in range(0, len(ciphertext_b64), PAYLOAD_MAX)]
    total_fragments = len(fragments)
    print(f"Mensagem original {len(message)} chars -> ciphertext base64 {len(ciphertext_b64)} chars -> {total_fragments} fragmentos de até {PAYLOAD_MAX} chars.")

    # Estado comum
    base_seq = SEQ_START
    next_seq_to_send = SEQ_START
    window_packets = {}
    client_socket.settimeout(TIMEOUT)

    # Para SR: manter tempos por pacote
    send_times = {}
    simular_erro_ativo = simular_erro

    if modo == 'GBN':
        timer = None
        while base_seq < total_fragments:
            while next_seq_to_send < total_fragments and (next_seq_to_send - base_seq) < window_size:
                payload = fragments[next_seq_to_send]
                corrupt = simular_erro_ativo and next_seq_to_send == SEQ_START
                pkt = make_packet(next_seq_to_send, payload, corrupt)
                if corrupt:
                    simular_erro_ativo = False
                    print("-> Simulação de erro determinístico desativada para retransmissões.")

                if random.random() < LOSS_RATE:
                    print(f"!!! [PERDA SIMULADA] Pacote seq={next_seq_to_send}")
                else:
                    client_socket.sendall(pkt.encode())
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
                            timer = None

                elif msg.startswith("NAK|"):
                    parts = msg.split('|')
                    try:
                        nak_seq = int(parts[1])
                    except:
                        nak_seq = -1
                    print(f"[NAK RECEBIDO] NAK para seq={nak_seq}. Forçando Timeout para retransmissão GBN.")
                    raise socket.timeout

                elif msg == "ACK_END":
                    print("[SERVER] confirmou encerramento (ACK_END recebido durante a transmissão)")
                    break
                else:
                    print("[RECEBIDO] (mensagem não reconhecida):", msg)

            except socket.timeout:
                print(f"!!! [TIMEOUT] Timer expirou. Retransmitindo (Go-Back-N) a partir de base_seq={base_seq}.")
                timer = time.time()
                next_seq_to_send = base_seq
                window_packets.clear()

            except Exception as e:
                print(f"Erro inesperado: {e}. Interrompendo transmissão.")
                break

    else:
        # SR mode
        acked = set()
        send_times = {}

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
            for seq, t0 in list(send_times.items()):
                if seq in acked:
                    continue
                if (now - t0) > TIMEOUT:
                    to_retransmit.append(seq)

            for seq in to_retransmit:
                pkt, payload = window_packets.get(seq, (None, None))
                if pkt is None:
                    send_times.pop(seq, None)
                    continue
                # regenerate pkt on retransmission to avoid resending a previously corrupted packet
                pkt = make_packet(seq, payload, corrupt=False)
                window_packets[seq] = (pkt, payload)
                print(f"!!! [TIMEOUT SR] Retransmitindo seq={seq}")
                if random.random() < LOSS_RATE:
                    print(f"!!! [PERDA SIMULADA] (na retransmissão) seq={seq}")
                else:
                    client_socket.sendall(pkt.encode())
                send_times[seq] = time.time()

            # receive ACK_IND / NAK / ACK_END
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
                        # regenerate packet before retransmission to fix deterministic-corruption case
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

    # After loop, we already sent all fragments; send END
    try:
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
