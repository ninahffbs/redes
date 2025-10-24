import socket

HOST = '127.0.0.1'
PORT = 5000

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    modo = "OPERACAO_X"
    tamanho_maximo = "2048"
    handshake = f"{modo};{tamanho_maximo}"
    client_socket.sendall(handshake.encode())

    resposta = client_socket.recv(1024).decode()
    print("Resposta do servidor", resposta)

    client_socket.close()

if __name__ == "__main__":
    main()
