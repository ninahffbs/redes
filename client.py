# client.py
import socket
import math
import time

HOST = '127.0.0.1'
PORT = 5000

PAYLOAD_MAX = 4
SEQ_START = 0

def checksum_of(data: bytes) -> int:
    return sum(data) % 256

def make_packet(seq: int, payload: str) -> str:
    length = len(payload)
    chk = checksum_of(payload.encode())
    return f"{seq}|{length}|{chk}|{payload}"

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    modo = input("Modo de operação (ex: OPERACAO_X): ").strip() or "OPERACAO_X"
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

    handshake = f"{modo};{tamanho_maximo}"
    client_socket.sendall(handshake.encode())

    resposta = client_socket.recv(4096).decode()
    print("Resposta do servidor (handshake):", resposta)

    window_size = 5
    try:
        parts = resposta.split(';')
        for p in parts:
            if p.startswith("janela="):
                window_size = int(p.split('=',1)[1])
    except:
        pass

    print(f"Janela definida pelo servidor: {window_size}")
    while True:
        message = input("Digite a mensagem a enviar (ou vazio para 'Olá mundo!'): ")
        if not message:
            message = "Olá mundo! Esta é uma mensagem de teste para transmissão segmentada."
        if len(message) > int(tamanho_maximo):
            print(f"Mensagem maior que tamanho máximo ({tamanho_maximo}). Digite menor.")
            continue
        break
    fragments = [message[i:i+PAYLOAD_MAX] for i in range(0, len(message), PAYLOAD_MAX)]
    total_fragments = len(fragments)
    print(f"Mensagem com {len(message)} chars -> {total_fragments} fragmentos de até {PAYLOAD_MAX} chars.")

    base_seq = SEQ_START
    next_seq = base_seq
    window = {}

    send_index = 0
    acked = set()

    client_socket.settimeout(5.0)

    while send_index < total_fragments or window:
        while send_index < total_fragments and len(window) < window_size:
            payload = fragments[send_index]
            pkt = make_packet(next_seq, payload)
            client_socket.sendall(pkt.encode())
            window[next_seq] = (pkt, payload)
            print(f"[ENVIADO] seq={next_seq} len={len(payload)} chk={checksum_of(payload.encode())} payload='{payload}'")
            next_seq += 1
            send_index += 1
            time.sleep(0.05)
        try:
            raw = client_socket.recv(4096)
            if not raw:
                print("Conexão fechada pelo servidor.")
                break
            msg = raw.decode()
            if msg.startswith("ACK|"):
                parts = msg.split('|')
                ack_seq = int(parts[1])
                rest = "|".join(parts[2:]) if len(parts) > 2 else ""
                print(f"[ACK RECEBIDO] ack_seq={ack_seq} {rest}")
                if ack_seq in window:
                    del window[ack_seq]
                    acked.add(ack_seq)
            elif msg.startswith("NAK|"):
                print(f"[NAK RECEBIDO] {msg}")
            elif msg == "ACK_END":
                print("[SERVER] confirmou encerramento")
            else:
                print("[RECEBIDO] (mensagem não reconhecida):", msg)
        except socket.timeout:
            print("Timeout aguardando ACKs (sem perda/erro ativo nesta entrega). Continuando...")
            continue
    client_socket.sendall("END".encode())
    try:
        raw = client_socket.recv(4096)
        if raw and raw.decode() == "ACK_END":
            print("Servidor confirmou encerramento da transmissão.")
    except socket.timeout:
        pass

    client_socket.close()
    print("Cliente finalizado.")

if __name__ == "__main__":
    main()
