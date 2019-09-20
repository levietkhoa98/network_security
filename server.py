import socket
import threading
import mysql.connector
from Crypto.PublicKey import RSA
import Crypto.Cipher.AES as AES
import Crypto.Cipher.PKCS1_OAEP as PKCS1_OAEP
import hashlib
import os

clientConnected_Socket = []
clientConnected_Address = []
clientConnected_SessionKey = []
clientConnected_SignedIn = []
welcomeMsg = "Welcome new client please sign in or sign up"
def main():
    #kkết nối csdl
    mydb = mysql.connector.connect(host='localhost',database='anm',user='anm',password='123abnkakashi',port='1998')
    if mydb.is_connected():
        print("Connected to DataBase")

    serverAddress = "127.0.0.1"
    serverPort = 1600

    # khởi tạo socket
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((serverAddress,serverPort))    
    server.listen(5)
    print("Server started")
    print("Waiting for client request..")
    while True:
        clientSock, clientAddress = server.accept()
        #tạo thread khi có client mới
        threading.Thread(target=clientthread,args=(clientSock,clientAddress,)).start()
    server.close()

#function thread
def clientthread(clientSock,clientAddress):
    #nhận public key của client
    getpbk = clientSock.recv(1024)
    #biến đổi dạng string sang key
    server_public_key = RSA.importKey(getpbk,passphrase=None)
    #
    hash_object = hashlib.sha1(getpbk)
    hex_digest = hash_object.hexdigest()
    #
    if getpbk != "":
        # print(getpbk)
        clientSock.send(b"YES")
        gethash = clientSock.recv(1024).decode() 
        # print(gethash)
    #
    if hex_digest == gethash:
        print("Correct key")
        #tạo session key
        key_128 = os.urandom(16)
        #mã hóa session key
        en = AES.new(key_128,AES.MODE_CTR)
        encrypto = en.encrypt(key_128)
        #hashing sha1
        en_object = hashlib.sha1(encrypto)
        en_digest = en_object.hexdigest()
        print("SESSION KEY : ",en_digest)
        #mã hóa public key và session key
        E = PKCS1_OAEP.new(server_public_key).encrypt(encrypto)
        # print("Encrypted public key and session key "+ str(E))
        print("HANDSHAKE complete")
        clientSock.send(E)

        print("Welcome new client ",clientAddress)

        clientConnected_Address.append(clientAddress)
        clientConnected_SignedIn.append(clientSock)
        clientConnected_SessionKey.append(en_digest)
        clientConnected_Socket.append(clientSock)

        clientSock.send(welcomeMsg.encode("UTF-8"))
        while True:      
            #message from client
            newmess = clientSock.recv(1024)
            print("New mess from client", newmess)
        clientSock.close()
    else:
        print("Public key not match")


if __name__ == "__main__":
    main() 