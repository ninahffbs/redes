import socket

HOST = '127.0.0.1'
PORT = 5000

def main():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))

    server_socket.listen(1)
    print(f"Servidor aguardando conexões em {HOST}:{PORT}...")

    conn, addr = server_socket.accept()
    print("Conectado por:", addr)

    data = conn.recv(1024).decode()
    modo, tamanho = data.split(";")
    print(f"Cliente iniciou handshake: modo={modo}, tamanho={tamanho}")

    resposta = f"ACK;modo={modo};tamanho={tamanho}"
    conn.sendall(resposta.encode())

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    main()
