# Projeto de Comunicação Confiável com GBN, SR e Criptografia AES

Este projeto implementa um protocolo de comunicação confiável sobre TCP, utilizando:
* Go-Back-N (GBN)
* Selective Repeat (SR)
* Diffie–Hellman (DH) para troca de chave
* AES-256 (CBC + PKCS7) para criptografia simétrica
* Fragmentação de mensagem + checksum + simulação de perda e corrupção

A comunicação ocorre entre dois scripts:
* server.py — recebe, verifica, reordena, decifra e remonta a mensagem
* client.py — cifra, fragmenta, transmite e retransmite caso necessário

O objetivo é permitir testes reais de protocolo confiável, com logs detalhados para estudo.

---
## Instalação e execução
### 1. Criar e ativar uma virtual environment

No Linux/MacOS
```bash
python3 -m venv venv
source venv/bin/activate
```
No Windows
```bash
python -m venv venv
venv\Scripts\activate
```
### 2. Instalar dependências
```bash
pip install pycryptodome
```

### 3. Executar o servidor 
No Linux/MacOS
```bash
python3 server.py
```
No Windows
```bash
python server.py
```
### 4. Executar o cliente
```bash
python3 client.py
```
No WindowsH
```bash
python client.py
```
O cliente perguntará:
* Modo de operação (GBN ou SR)
* Tamanho máximo da mensagem
* Simulação de erro determinístico no primeiro pacote (s/n)
* A mensagem a enviar

---

## Visão geral do funcionamento
### 1. Handshake + Troca de chave (Diffie-Hellman)
1. Cliente envia:
```bash
GBN;2048
```
2. Servidor responde com ACK contendo
* modo
* tamanho
* janela
* server_pub (parâmetro DH para criptografia)

3. Cliente envia seu client_pub
4. Ambos calculam o shared secret
A chave de AES de 256 bits é derivada assim:
```bash
aes_key = sha256(str(shared_secret).encode()).digest()
```
### 2. Criptografia – AES-256 (CBC)
Toda a mensagem é cifrada antes de ser fragmentada:
* Gera-se IV aleatório de 16 bytes
* Usa AES em modo CBC
* Usa PKCS7 para pad
* Concatena IV + ciphertext
* Codifica em base64
Assim, a fragmentação trabalha sobre texto base64 seguro e ASCII.

### 3. Fragmentação + checksum
O ciphertext base64 é fragmentado em pedaços de até 4 bytes.
Cada fragmento é encapsulado como:
```bash
seq | length | checksum | payload-base64
```
* checksum = soma dos bytes do payload % 256
* seq é sempre global (não cíclico)
* o servidor valida length e checksum

### 4. Transmissão — Algoritmos Implementados
***Go-Back-N (GBN)***
* Janela deslizante
* ACK cumulativo
* Em erro ou perda: reinicia envio a partir de base_seq
* Um único timer controla o primeiro pacote da janela
***Selective Repeat (SR)***
* Janela deslizante bidirecional
* ACKs individuais (ACK_IND)
* Retransmissão somente dos pacotes vencidos ou NAKados
* Um timer por pacote
* Reordenação no servidor
* Avança base quando possível
Esse modo fornece o comportamento mais realista de um protocolo confiável moderno.

### 5. Reassembly + Decriptografia
No servidor:
* Os fragmentos válidos são armazenados
* Ordena-se por seq
* Junta-se o ciphertext base64
* Decodifica base64
* Separa IV
* AES decripta e remove padding
* Exibe a mensagem final em texto claro

---

### Guia de logs!
O sistema gera logs educativos para visualizar o comportamento interno.
***Exemplos do cliente***
* Envio:
```bash
[ENVIADO] seq=3 len=4 chk=120 payload(b64)='u2F/'
```
* Simulação de perda:
```bash
!!! [PERDA SIMULADA] Pacote seq=2
```
* Timeout (GBN)
```bash
!!! [TIMEOUT] Timer expirou. Retransmitindo (Go-Back-N) a partir de base_seq=5.
```
* Timeout (SR)
```bash
!!! [TIMEOUT SR] Retransmitindo seq=7
```
* NAK
```bash
[NAK RECEBIDO] nak_seq=0
-> SR: retransmitindo seq=0 por causa de NAK
```
***Exemplos do servidor***
* Pacote recebido
```bash
[PACOTE RECEBIDO] seq=0 len=4 chk=64 payload='QkFBRA=='
```
* Erro de integridade
```bash
-> Erro de integridade. Enviando NAK para esse seq.
```
* ACKs
```bash
-> Pacote íntegro e em ordem (GBN).
ACK|5
```
* Reordenação (SR):
```bash
-> Pacote aceito (SR). Enviando ACK_IND.
```
* Mensagem final:
```bash
--- Comunicação completa. Mensagem decriptada no servidor: ---
Olá mundo! Esta é uma mensagem de teste para transmissão segmentada.
```
---
### Funcionalidades Suportadas
* Perda aleatória de pacotes
* Corrupção determinística do primeiro pacote
* Retransmissão GBN
* Retransmissão SR com timer individual
* Reenvio seletivo após NAK
* Janela deslizante configurável
* DH para troca de chave
* AES-256 para sigilo da mensagem
* Base64 para transporte seguro
* Logs completos para fins didáticos
