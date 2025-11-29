import socket
import time

HOST = '127.0.0.1'
PORT = 5000

PAYLOAD_MAX = 4
INITIAL_WINDOW = 5
MAX_SEQ = 256

def checksum_of(data: bytes) -> int:
    return sum(data) % 256

def parse_packet(packet: str):
    parts = packet.split('|', 3)
    if len(parts) < 4:
        return None

    try:
        seq = int(parts[0])
        length = int(parts[1])
        chk = int(parts[2])
        payload = parts[3]
        return seq, length, chk, payload
    except ValueError:
        print(f"Erro de conversão em pacote: {packet}")
        return None


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Servidor aguardando conexões em {HOST}:{PORT}...")

    try:
        conn, addr = server_socket.accept()
    except KeyboardInterrupt:
        server_socket.close()
        return

    print("Conectado por:", addr)

    # --- Handshake ---
    data = conn.recv(4096).decode()
    try:
        modo, tamanho = data.split(";")
    except:
        conn.sendall(b"ERR;handshake_invalido\n")
        conn.close()
        server_socket.close()
        return

    print(f"Cliente iniciou handshake: modo={modo}, tamanho_max={tamanho}")

    resposta = f"ACK;modo={modo};tamanho={tamanho};janela={INITIAL_WINDOW}\n"
    conn.sendall(resposta.encode())

    received_fragments = {}
    expected_seq = 0

    print("Servidor pronto para receber pacotes... (esperando 'END')")

    buffer = ""

    while True:
        try:
            raw = conn.recv(4096)
        except ConnectionResetError:
            print("Conexão redefinida pelo cliente.")
            break

        if not raw:
            print("Conexão fechada pelo cliente.")
            break

        buffer += raw.decode()

        # processa todas as linhas completas
        while '\n' in buffer:
            msg, buffer = buffer.split('\n', 1)

            if not msg:
                continue

            if msg == "END":
                conn.sendall("ACK_END\n".encode())
                buffer = ""
                break

            parsed = parse_packet(msg)

            if not parsed:
                print("Pacote malformado. Enviando NAK|-1")
                conn.sendall("NAK|-1\n".encode())
                continue

            seq_cyclic, length, chk, payload = parsed
            local_chk = checksum_of(payload.encode())

            print(f"[PACOTE RECEBIDO] seq={seq_cyclic} len={length} chk={chk} payload='{payload}'")

            # Erro de integridade
            if local_chk != chk or len(payload) != length:
                print(" -> Erro de integridade. Enviando NAK.")
                conn.sendall(f"NAK|{expected_seq % MAX_SEQ}\n".encode())
                continue

            # Ordem incorreta (GBN)
            if seq_cyclic != (expected_seq % MAX_SEQ):
                print(f" -> Pacote fora de ordem (esperado={expected_seq % MAX_SEQ}).")
                conn.sendall(f"ACK|{expected_seq}\n".encode())
                continue

            # Pacote correto e em ordem
            print(" -> Pacote OK.")
            received_fragments[expected_seq] = payload
            expected_seq += 1

            conn.sendall(f"ACK|{expected_seq}\n".encode())

        if msg == "END":
            break

    # --- Montagem final ---
    if received_fragments:
        assembled = ''.join(payload for seq, payload in sorted(received_fragments.items()))
        print("\n--- Mensagem Reconstituída ---")
        print(assembled)
    else:
        print("\n--- Nenhum fragmento recebido. ---")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    main()
