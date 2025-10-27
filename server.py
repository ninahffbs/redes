import socket

HOST = '127.0.0.1'
PORT = 5000

PAYLOAD_MAX = 4 
INITIAL_WINDOW = 5  

def checksum_of(data: bytes) -> int:
    return sum(data) % 256

def parse_packet(packet: str):
    parts = packet.split('|', 3)
    if len(parts) < 4:
        return None
    seq = int(parts[0])
    length = int(parts[1])
    chk = int(parts[2])
    payload = parts[3]
    return seq, length, chk, payload

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Servidor aguardando conexões em {HOST}:{PORT}...")

    conn, addr = server_socket.accept()
    print("Conectado por:", addr)

    data = conn.recv(4096).decode()
    try:
        modo, tamanho = data.split(";")
    except Exception:
        conn.sendall(b"ERR;handshake_invalido")
        conn.close()
        server_socket.close()
        return

    print(f"Cliente iniciou handshake: modo={modo}, tamanho_max={tamanho}")

    window_size = INITIAL_WINDOW
    resposta = f"ACK;modo={modo};tamanho={tamanho};janela={window_size}"
    conn.sendall(resposta.encode())

    received_fragments = {}
    expected_seq = 0
    print("Servidor pronto para receber pacotes... (esperando 'END' para finalizar)")

    while True:
        raw = conn.recv(4096)
        if not raw:
            print("Conexão fechada pelo cliente.")
            break
        msg = raw.decode()
        if msg == "END":
            conn.sendall("ACK_END".encode())
            break
        parsed = parse_packet(msg)
        if not parsed:
            conn.sendall("NAK|malformed".encode())
            continue

        seq, length, chk, payload = parsed

        local_chk = checksum_of(payload.encode())

        print(f"[PACOTE RECEBIDO] seq={seq} len={length} chk={chk} payload='{payload}'")

        if local_chk != chk or length != len(payload):
            print(" -> Checagem falhou. Enviando NAK.")
            conn.sendall(f"NAK|{seq}".encode())
            continue

        received_fragments[seq] = payload
        ack_msg = f"ACK|{seq}|len={length}|chk={chk}"
        conn.sendall(ack_msg.encode())

    if received_fragments:
        assembled = ''.join(payload for seq, payload in sorted(received_fragments.items()))
        print("\n--- Comunicação completa. Mensagem reconstituída no servidor: ---")
        print(assembled)
    else:
        print("\n--- Nenhum fragmento recebido. ---")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    main()
