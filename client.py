# client.py
import socket
import math
import time

HOST = '127.0.0.1'
PORT = 5000

PAYLOAD_MAX = 4  # carga útil máxima por pacote (caracteres)
SEQ_START = 0

def checksum_of(data: bytes) -> int:
    return sum(data) % 256

def make_packet(seq: int, payload: str) -> str:
    length = len(payload)
    chk = checksum_of(payload.encode())
    # formato: "SEQ|LEN|CHK|PAYLOAD"
    return f"{seq}|{length}|{chk}|{payload}"

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # pedir parâmetros ao usuário (ou usar padrão)
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

    # parse da resposta para obter janela
    window_size = 5
    try:
        # exemplo: "ACK;modo=OPERACAO_X;tamanho=2048;janela=5"
        parts = resposta.split(';')
        for p in parts:
            if p.startswith("janela="):
                window_size = int(p.split('=',1)[1])
    except:
        pass

    print(f"Janela definida pelo servidor: {window_size}")

    # entrada da mensagem de aplicação
    while True:
        message = input("Digite a mensagem a enviar (ou vazio para 'Olá mundo!'): ")
        if not message:
            message = "Olá mundo! Esta é uma mensagem de teste para transmissão segmentada."
        if len(message) > int(tamanho_maximo):
            print(f"Mensagem maior que tamanho máximo ({tamanho_maximo}). Digite menor.")
            continue
        break

    # fragmenta em payloads de até PAYLOAD_MAX
    fragments = [message[i:i+PAYLOAD_MAX] for i in range(0, len(message), PAYLOAD_MAX)]
    total_fragments = len(fragments)
    print(f"Mensagem com {len(message)} chars -> {total_fragments} fragmentos de até {PAYLOAD_MAX} chars.")

    base_seq = SEQ_START
    next_seq = base_seq
    window = {}  # seq -> packet string (aguardando ack)

    send_index = 0  # índice do fragmento a enviar
    acked = set()

    client_socket.settimeout(5.0)  # timeout de recepção (mas não vamos retransmitir nesta entrega)

    while send_index < total_fragments or window:
        # enfileirar até preencher a janela
        while send_index < total_fragments and len(window) < window_size:
            payload = fragments[send_index]
            pkt = make_packet(next_seq, payload)
            client_socket.sendall(pkt.encode())
            window[next_seq] = (pkt, payload)
            print(f"[ENVIADO] seq={next_seq} len={len(payload)} chk={checksum_of(payload.encode())} payload='{payload}'")
            next_seq += 1
            send_index += 1
            # pequena pausa para leitura humana (opcional)
            time.sleep(0.05)

        # aguardar ACK(s)
        try:
            raw = client_socket.recv(4096)
            if not raw:
                print("Conexão fechada pelo servidor.")
                break
            msg = raw.decode()
            # tratar ACK padrão: "ACK|seq|len=...|chk=..."
            if msg.startswith("ACK|"):
                parts = msg.split('|')
                ack_seq = int(parts[1])
                # imprime metadados do ACK (exigência)
                rest = "|".join(parts[2:]) if len(parts) > 2 else ""
                print(f"[ACK RECEBIDO] ack_seq={ack_seq} {rest}")
                if ack_seq in window:
                    del window[ack_seq]
                    acked.add(ack_seq)
            elif msg.startswith("NAK|"):
                # em entrega sem erros, não esperamos NAK, mas mostramos
                print(f"[NAK RECEBIDO] {msg}")
                # comportamento de retransmissão poderia ser implementado aqui
            elif msg == "ACK_END":
                print("[SERVER] confirmou encerramento")
            else:
                print("[RECEBIDO] (mensagem não reconhecida):", msg)
        except socket.timeout:
            # sem retransmissão nesta fase (já que o canal é sem erro para esta entrega)
            print("Timeout aguardando ACKs (sem perda/erro ativo nesta entrega). Continuando...")
            # se desejar, poderíamos retransmitir pacotes aqui, mas pedido foi para NÃO implementar
            # a simulação de erros agora. Então apenas vamos tentar continuar.
            continue

    # informar fim da transmissão
    client_socket.sendall("END".encode())
    # aguardar confirmação de fim
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
