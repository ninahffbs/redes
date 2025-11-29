#!/usr/bin/env python3
import socket
import time
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 5000

PAYLOAD_MAX = 4
INITIAL_WINDOW = 5
MAX_SEQ = 256  

DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
DH_G = 2

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

def aes_decrypt_from_b64(b64text: str, key: bytes) -> bytes:
    #decodifica a string base64, separa IV e ciphertext e descriptografa usando AES-CBC.
    try:
        data = base64.b64decode(b64text)
        if len(data) < 16:
            raise ValueError("ciphertext too short")
        iv = data[:16] #primeiros 16 bytes
        ct = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    except Exception as e:
        raise

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

    try:
        data = conn.recv(8192).decode()
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
    print(f"Cliente iniciou handshake: modo={modo}, tamanho_max={tamanho}")

    window_size = INITIAL_WINDOW

    #chave privada dh do servidor
    server_priv = int.from_bytes(get_random_bytes(64), 'big') % (DH_PRIME - 2) + 2
    #calcula a chave publica dh
    server_pub = pow(DH_G, server_priv, DH_PRIME)

    resposta = f"ACK;modo={modo};tamanho={tamanho};janela={window_size};dh={server_pub}\n"
    conn.sendall(resposta.encode())

    #aguarda chave publica dh do cliente
    conn.settimeout(10.0)
    buffer = ""
    client_pub = None
    try:
        while True:
            raw = conn.recv(4096)
            if not raw:
                print("Conexão fechada pelo cliente durante DH.")
                conn.close()
                server_socket.close()
                return
            buffer += raw.decode()
            if '\n' in buffer:
                msg, buffer = buffer.split('\n', 1)
                if msg.startswith("DH|"):
                    try:
                        client_pub = int(msg.split('|',1)[1])
                    except:
                        print("DH inválido recebido.")
                        conn.sendall(b"ERR;dh_invalid\n")
                        conn.close()
                        server_socket.close()
                        return
                    break
                else:
                    # ignore unexpected messages before DH
                    continue
    except socket.timeout:
        print("Timeout aguardando DH do cliente.")
        conn.close()
        server_socket.close()
        return
    except Exception as e:
        print("Erro no handshake DH:", e)
        conn.close()
        server_socket.close()
        return

    #deriva segredo compartilhado
    shared = pow(client_pub, server_priv, DH_PRIME)
    shared_bytes = str(shared).encode()
    #deriva chave AES
    aes_key = hashlib.sha256(shared_bytes).digest()  # 32 bytes -> AES-256
    print("DH concluído — chave simétrica derivada (AES-256).")

    conn.settimeout(None)
    received_fragments = {}
    expected_seq = 0
    buffer = ""
    print("Servidor pronto para receber pacotes... (esperando 'END')")

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
                print("Pacote malformado. Enviando NAK|-1")
                conn.sendall("NAK|-1\n".encode())
                continue

            seq_global, length, chk, payload_b64 = parsed
            
            #calcula o checksum local do payload
            local_chk = checksum_of(payload_b64.encode())

            print(f"[PACOTE RECEBIDO] seq={seq_global} (cíclico={seq_global % MAX_SEQ}) len={length} chk={chk} payload(b64)='{payload_b64}'")

            if local_chk != chk or len(payload_b64) != length:
                print(" -> Erro de integridade. Enviando NAK para esse seq.")
                conn.sendall(f"NAK|{seq_global}\n".encode())
                continue

            if modo == 'GBN':
                if seq_global != expected_seq:
                    #reenvia o ack cumulativo para sinalizar oq ta faltando
                    print(f" -> Pacote fora de ordem (esperado={expected_seq}). Descartando e enviando ACK cumulativo.")
                    conn.sendall(f"ACK|{expected_seq}\n".encode())
                    continue

                print(" -> Pacote íntegro e em ordem (GBN).")
                received_fragments[expected_seq] = payload_b64
                expected_seq += 1
                conn.sendall(f"ACK|{expected_seq}\n".encode())

            else:  #SR
                win_start = expected_seq
                win_end = expected_seq + window_size - 1
                if seq_global < win_start:
                    #pacote recebido/reconhecido -> envia ack individual para impedir retransmissao
                    print(f" -> Pacote com seq < janela (seq={seq_global} < start={win_start}). Reenviando ACK_IND.")
                    conn.sendall(f"ACK_IND|{seq_global}\n".encode())
                    continue
                if seq_global > win_end:
                    print(f" -> Pacote fora da janela SR (esperado interval [{win_start},{win_end}]). Descartando.")
                    conn.sendall(f"ACK_IND|{seq_global}\n".encode())
                    continue

                if seq_global in received_fragments:
                    print(" -> Pacote já recebido (duplicado). Reenviando ACK_IND.")
                    conn.sendall(f"ACK_IND|{seq_global}\n".encode())
                    continue

                received_fragments[seq_global] = payload_b64
                print(" -> Pacote aceito (SR). Enviando ACK_IND.")
                conn.sendall(f"ACK_IND|{seq_global}\n".encode())

                while expected_seq in received_fragments:
                    expected_seq += 1

        if msg == "END":
            break

    if received_fragments:
        #monta a string base64 completa ordenando pelos numeros de sequencia
        assembled_b64 = ''.join(payload for seq, payload in sorted(received_fragments.items()))
        try:
            #descriptografa a mensagem
            plaintext_bytes = aes_decrypt_from_b64(assembled_b64, aes_key)
            try:
                plaintext = plaintext_bytes.decode()
            except:
                plaintext = repr(plaintext_bytes)
            print("\n--- Comunicação completa. Mensagem decriptada no servidor: ---")
            print(plaintext)
        except Exception as e:
            print("\n--- Erro ao decifrar a mensagem:", e)
            print("Conteúdo (base64) reconstituído (não foi possível decifrar):")
            print(assembled_b64[:200] + "..." if len(assembled_b64) > 200 else assembled_b64)
    else:
        print("\n--- Nenhum fragmento recebido. ---")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    main()
