#!/usr/bin/env python3
import socket
import time

HOST = '127.0.0.1'
PORT = 5000

PAYLOAD_MAX = 4
INITIAL_WINDOW = 5
MAX_SEQ = 256  # usado apenas para impressão/cálculo cíclico, seqs são globais

def checksum_of(data: bytes) -> int:
    return sum(data) % 256

def parse_packet(packet: str):
    parts = packet.split('|', 3)
    if len(parts) < 4:
        return None
    try:
        seq = int(parts[0])           # seq global
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

    # --- Handshake (espera uma linha simples) ---
    try:
        data = conn.recv(4096).decode()
    except Exception:
        conn.close()
        server_socket.close()
        return

    try:
        modo, tamanho = data.split(";")
    except Exception:
        conn.sendall(b"ERR;handshake_invalido\n")
        conn.close()
        server_socket.close()
        return

    modo = modo.strip().upper()
    try:
        tamanho_int = int(tamanho)
    except:
        tamanho_int = 0

    print(f"Cliente iniciou handshake: modo={modo}, tamanho_max={tamanho_int}")

    window_size = INITIAL_WINDOW
    resposta = f"ACK;modo={modo};tamanho={tamanho_int};janela={window_size}\n"
    conn.sendall(resposta.encode())

    # Estado do receptor
    received_fragments = {}   # seq_global -> payload (usado tanto GBN quanto SR)
    expected_seq = 0          # próximo seq global esperado (cumulativo para GBN)
    buffer = ""               # buffer para montar linhas recebidas

    print("Servidor pronto para receber pacotes... (esperando 'END')")

    # modo pode ser 'GBN' ou 'SR'; trate qualquer outro como 'GBN' por padrão
    if modo not in ('GBN', 'SR'):
        modo = 'GBN'

    while True:
        try:
            raw = conn.recv(4096)
        except ConnectionResetError:
            print("Conexão redefinida pelo cliente.")
            break
        except Exception:
            print("Erro de recv no servidor.")
            break

        if not raw:
            print("Conexão fechada pelo cliente.")
            break

        buffer += raw.decode()

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
                # pacote malformado
                print("Pacote malformado. Enviando NAK|-1")
                conn.sendall("NAK|-1\n".encode())
                continue

            seq_global, length, chk, payload = parsed
            local_chk = checksum_of(payload.encode())

            print(f"[PACOTE RECEBIDO] seq={seq_global} (cíclico={seq_global % MAX_SEQ}) len={length} chk={chk} payload='{payload}'")

            # integridade
            if local_chk != chk or len(payload) != length:
                print(" -> Erro de integridade. Enviando NAK para esse seq.")
                # envie NAK pedindo reenvio desse seq
                conn.sendall(f"NAK|{seq_global}\n".encode())
                continue

            if modo == 'GBN':
                # GBN: aceita só se seq == expected_seq
                if seq_global != expected_seq:
                    print(f" -> Pacote fora de ordem (esperado={expected_seq}). Descartando e enviando ACK cumulativo.")
                    conn.sendall(f"ACK|{expected_seq}\n".encode())
                    continue

                # pacote em ordem e íntegro
                print(" -> Pacote íntegro e em ordem (GBN).")
                received_fragments[expected_seq] = payload
                expected_seq += 1
                # ACK cumulativo indica próximo seq global esperado
                conn.sendall(f"ACK|{expected_seq}\n".encode())

            else:  # modo == 'SR'
                # janelamento SR: aceitar pacotes dentro da janela [expected_seq, expected_seq+window_size-1]
                win_start = expected_seq
                win_end = expected_seq + window_size - 1

                if seq_global < win_start:
                    # pacote já recebido / muito antigo (reenvio duplicado). reenvia ACK individual.
                    print(f" -> Pacote com seq < janela (seq={seq_global} < start={win_start}). Reenviando ACK_IND.")
                    conn.sendall(f"ACK_IND|{seq_global}\n".encode())
                    continue

                if seq_global > win_end:
                    # pacote fora da janela (muito adiantado) — descartar
                    print(f" -> Pacote fora de janela SR (esperado interval [{win_start},{win_end}]). Descartando.")
                    # opcional: enviar ACK do último cumulativo
                    conn.sendall(f"ACK_IND|{seq_global}\n".encode())  # informar recebimento (pode ser ignorado pelo cliente se fora da janela)
                    continue

                # pacote aceitável dentro da janela
                if seq_global in received_fragments:
                    # já recebido — reenviar ACK
                    print(" -> Pacote já recebido (duplicado). Reenviando ACK_IND.")
                    conn.sendall(f"ACK_IND|{seq_global}\n".encode())
                    continue

                # armazena pacote
                received_fragments[seq_global] = payload
                print(" -> Pacote aceito (SR). Enviando ACK_IND.")
                conn.sendall(f"ACK_IND|{seq_global}\n".encode())

                # avançar expected_seq enquanto houver fragmentos contíguos
                while expected_seq in received_fragments:
                    expected_seq += 1

        if msg == "END":
            break

    # Montagem final da mensagem (se houver fragmentos)
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
