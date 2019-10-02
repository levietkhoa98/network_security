import socket
import threading
import mysql.connector
from Crypto.PublicKey import RSA
import Crypto.Cipher.AES as AES
import Crypto.Cipher.PKCS1_OAEP as PKCS1_OAEP
import hashlib
import os
import base64
import json
import time

clientConnected_Socket = []
clientConnected_Address = []
clientConnected_SessionKey = []
clientConnected_SignedIn = []
threadLock = False

mydb = mysql.connector.connect(host='localhost',database='anm',user='anm',password='123abnkakashi',port='1998')
mycursor = mydb.cursor()

welcomeMsg = "Welcome new client please sign in or sign up"

def main():
    #kkết nối csdl
    if mydb.is_connected():
        print("Connected to DataBase")

    serverAddress = "127.0.0.1"
    # serverAddress = "192.168.1.1"
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
        threadConn = threading.Thread(target=clientthread,args=(clientSock,clientAddress,))
        threadConn.start()
        if (threadLock == True):
            threadConn.join()
        print(clientConnected_Socket)
        print(threading.active_count())
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
        #dùng public key để mã hóa session key 
        E = PKCS1_OAEP.new(server_public_key).encrypt(encrypto)
        # print("Encrypted public key and session key "+ str(E))
        print("HANDSHAKE complete")
        clientSock.send(E)

        print("Welcome new client ",clientAddress)

        clientConnected_Address.append(clientAddress)
        clientConnected_SignedIn.append(clientSock)
        clientConnected_SessionKey.append(en_digest)
        clientConnected_Socket.append(clientSock)

        # print(clientConnected_Socket)
        # gửi tin nhắn chào mừng
        # clientSock.send(welcomeMsg.encode("UTF-8"))
        while True:           
            threadSend = threading.Thread(target=sendeMSg,args=(en_digest,clientSock,clientConnected_SessionKey,clientConnected_Socket,))
            threadSend.start()
            threadSend.join()
    else:
        print("Public key not match")

def recveMsg(key,socket):
    eMsg = socket.recv(1024).decode()
    b64 = json.loads(eMsg)
    nonce = base64.b64decode(b64['nonce'])
    ct = base64.b64decode(b64['ciphertext'])
    # print(eMsg)
    key = key[:16].encode()   
    # print(key)
    aesDecrypt = AES.new(key,AES.MODE_CTR,nonce=nonce)
    # print(aesDecrypt)
    dMsg = aesDecrypt.decrypt(ct).decode()
    print("New mess from client ",socket ," : " , dMsg)
    return dMsg


def sendeMSg(recvKey,recvSocket,keyArr,socketArr):
    #giải mã tin nhắn
    dMsg = recveMsg(recvKey,recvSocket)
    #tách chuỗi để xét trường hợp
    MsgArr = dMsg.split()
    # đăng ký
    if (MsgArr[0] == "signup"):
        sql = "INSERT INTO customers (name, password) VALUES (%s, %s)"
        val = (MsgArr[1], MsgArr[2])
        mycursor.execute(sql, val)
        mydb.commit()
        print(mycursor.rowcount, "record inserted.")
        if (mycursor.rowcount):
            SuccessMsg = ("Create new user successfully")
            sendMsg = SuccessMsg.encode()
            key = recvKey[:16].encode()
            # print(key)
            aesEncrypt = AES.new(key,AES.MODE_CTR)
            # print(aesEncrypt)
            ct_bytes = aesEncrypt.encrypt(sendMsg)
            nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()
            # print(eMsg)    
            recvSocket.send(eMsg)
    if (MsgArr[0] == "login"):
        sql = "SELECT * FROM customers WHERE name = %s AND password = %s"
        val = (MsgArr[1], MsgArr[2])
        mycursor.execute(sql, val)
        myresult = mycursor.fetchall()
        if (myresult):
            SuccessMsg = ("Login successfully")
            sendMsg = SuccessMsg.encode()
            key = recvKey[:16].encode()
            # print(key)
            aesEncrypt = AES.new(key,AES.MODE_CTR)
            # print(aesEncrypt)
            ct_bytes = aesEncrypt.encrypt(sendMsg)
            nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()
            # print(eMsg)    
            recvSocket.send(eMsg)
            #gửi danh sách người dùng sang cho client
            sql = "SELECT name FROM customers"
            mycursor.execute(sql)
            myresult = mycursor.fetchall()
            
            sendMsg= listName.join(myresult).encode
            key = recvKey[:16].encode()
            aesEncrypt = AES.new(key,AES.MODE_CTR)
            ct_bytes = aesEncrypt.encrypt(sendMsg)
            nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()   
            recvSocket.send(eMsg)
    else:
        sendMsg = dMsg.encode()
        for i,s in enumerate(socketArr) :
            if (s != recvSocket):
                key = keyArr[i][:16].encode()
                # print(key)
                aesEncrypt = AES.new(key,AES.MODE_CTR)
                # print(aesEncrypt)
                ct_bytes = aesEncrypt.encrypt(sendMsg)
                nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
                ct = base64.b64encode(ct_bytes).decode('utf-8')
                eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()
                # print(eMsg)    
                socketArr[i].send(eMsg)
                print("send to Socket ",socketArr[i])

if __name__ == "__main__":
    mydb = mysql.connector.connect(host='localhost',database='anm',user='anm',password='123abnkakashi',port='1998')
    mycursor = mydb.cursor()
    main() 