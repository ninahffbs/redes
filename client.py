import socket
import math
import time
import random

HOST = '127.0.0.1'
PORT = 5000

PAYLOAD_MAX = 4
SEQ_START = 0
TIMEOUT = 3.0
MAX_SEQ = 256

LOSS_RATE = 0.1  # 10% perda simulada


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


def make_packet(seq: int, payload: str, corrupt: bool = False) -> str:
    seq_cyclic = seq % MAX_SEQ
    length = len(payload)
    chk = checksum_of(payload.encode())

    if corrupt:
        chk = (chk + 1) % 256
        print(f"!!! [ERRO SIMULADO] Checksum corrompido seq={seq_cyclic}")

    return f"{seq_cyclic}|{length}|{chk}|{payload}\n"


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Erro: servidor não está rodando.")
        return

    modo = input("Modo de operação (ex: OPERACAO_X): ").strip() or "OPERACAO_X"
    while True:
        tamanho_maximo = input("Tamanho máximo da mensagem (>=30): ").strip()
        if not tamanho_maximo:
            tamanho_maximo = "2048"
            break
        try:
            tm = int(tamanho_maximo)
            if tm < 30:
                print("Tamanho mínimo é 30.")
                continue
            break
        except:
            print("Digite um número válido.")
            continue

    simular_erro = input("Simular erro determinístico no primeiro pacote? (s/n): ").lower() == 's'

    # Handshake
    handshake = f"{modo};{tamanho_maximo}"
    client_socket.sendall(handshake.encode())

    resposta = recv_until(client_socket)
    if resposta is None:
        print("Erro no handshake.")
        return

    print("Handshake servidor:", resposta)

    window_size = 5
    parts = resposta.split(';')
    for p in parts:
        if p.startswith("janela="):
            window_size = int(p.split('=')[1])

    print("Janela =", window_size)

    # Entrada da mensagem
    while True:
        message = input("Mensagem (vazio = teste padrão): ")
        if not message:
            message = "Olá mundo! Esta é uma mensagem de teste para transmissão segmentada."
        if len(message) > int(tamanho_maximo):
            print("Mensagem maior que limite.")
            continue
        break

    fragments = [message[i:i+PAYLOAD_MAX] for i in range(0, len(message), PAYLOAD_MAX)]
    total_fragments = len(fragments)

    print(f"Mensagem com {len(message)} chars → {total_fragments} fragmentos.")

    base_seq = SEQ_START
    next_seq_to_send = SEQ_START
    window_packets = {}
    timer = None

    client_socket.settimeout(TIMEOUT)

    # --- Loop GBN ---
    while base_seq < total_fragments:

        # Envio dentro da janela
        while next_seq_to_send < total_fragments and (next_seq_to_send - base_seq) < window_size:

            payload = fragments[next_seq_to_send]
            corrupt = simular_erro and next_seq_to_send == SEQ_START

            pkt = make_packet(next_seq_to_send, payload, corrupt)

            if corrupt:
                simular_erro = False

            if random.random() < LOSS_RATE:
                print(f"!!! [PERDA SIMULADA] seq={next_seq_to_send}")
            else:
                client_socket.sendall(pkt.encode())
                window_packets[next_seq_to_send] = pkt
                print(f"[ENVIADO] seq={next_seq_to_send} payload='{payload}' chk={checksum_of(payload.encode())}")

            if timer is None and next_seq_to_send == base_seq:
                timer = time.time()
                print("-> Timer iniciado")

            next_seq_to_send += 1
            time.sleep(0.05)

        # Recebendo ACK/NAK
        try:
            if timer is not None and (time.time() - timer) > TIMEOUT:
                raise socket.timeout

            msg = recv_until(client_socket)

            if msg is None:
                print("Conexão perdida.")
                break

            if msg.startswith("ACK|"):
                parts = msg.split('|')
                try:
                    ack_seq = int(parts[1])
                except:
                    print("ACK inválido recebido, ignorando.")
                    continue

                print(f"[ACK] {ack_seq}")

                if ack_seq > base_seq:
                    for seq in range(base_seq, ack_seq):
                        window_packets.pop(seq, None)

                    base_seq = ack_seq
                    print("-> Base atualizada para", base_seq)

                    if base_seq < next_seq_to_send:
                        timer = time.time()
                    else:
                        timer = None

            elif msg.startswith("NAK|"):
                print("[NAK recebido] força retransmissão GBN.")
                raise socket.timeout

        except socket.timeout:
            print("!!! TIMEOUT → retransmitindo janela completa...")
            next_seq_to_send = base_seq
            timer = time.time()
            window_packets.clear()

    # Encerramento
    client_socket.sendall("END\n".encode())

    try:
        final_ack = recv_until(client_socket)
        if final_ack == "ACK_END":
            print("Servidor confirmou encerramento.")
    except:
        print("Erro aguardando ACK_END.")

    client_socket.close()
    print("Cliente finalizado.")


if __name__ == "__main__":
    main()
