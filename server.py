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
clientConnected_Name = []
clientConnected_SessionKey = []
clientSignedIn_SessionKey = []
threadLock = False

mydb = mysql.connector.connect(host='localhost',database='anm',user='anm',password='123abnkakashi',port='1998')
mycursor = mydb.cursor()

welcomeMsg = "Welcome new client please sign in or sign up"

#hàm main khởi tạo server
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
        print(threading.active_count())
        if (threadLock == True):
            threadConn.join()
    server.close()

# hàm thread của client
def clientthread(clientSock,clientAddress):
    global threadLock
    threadLock = False
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

        global clientConnected_SessionKey
        clientConnected_SessionKey.append(en_digest)
        
        # print(clientConnected_Socket)
        # gửi tin nhắn chào mừng
        # clientSock.send(welcomeMsg.encode("UTF-8"))       
        threadSend = threading.Thread(target=sendeMSg,args=(en_digest,clientSock,clientConnected_SessionKey,))
        threadSend.start()
        threadSend.join()
    else:
        print("Public key not match")

# hàm nhận và giải mã tin nhắn, kiểm tra kết nối client đến server
def recveMsg(key,socket):
    global threadLock
    global clientConnected_Socket
    global clientConnected_SessionKey
    global clientSignedIn_SessionKey
    try:
        eMsg = socket.recv(1024)
        if eMsg:
            eMsg = eMsg.decode()
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
    except:
        threadLock = True
        clientConnected_SessionKey.remove(key)    
        for i,k in enumerate(clientSignedIn_SessionKey):
            if (k == key):
                clientConnected_Socket.remove(clientConnected_Socket[i])
                clientSignedIn_SessionKey.remove(key)
                clientConnected_Name.remove(clientConnected_Name[i])
                for i,s in enumerate(clientConnected_Socket):        
                    sendMsg = json.dumps(clientConnected_Name).encode()
                    key = clientConnected_SessionKey[i][:16].encode()
                    aesEncrypt = AES.new(key,AES.MODE_CTR)
                    ct_bytes = aesEncrypt.encrypt(sendMsg)
                    nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
                    ct = base64.b64encode(ct_bytes).decode('utf-8')
                    eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()
                    try :    
                        s.send(eMsg)
                    except :
                        print("Client disconnected cant send")
        socket.close()
        return "Client disconnected"

# hàm gửi tin nhắn cho client
def sendeMSg(recvKey,recvSocket,keyArr):
    global clientConnected_Socket
    global clientConnected_SessionKey
    global clientConnected_Name
    global clientSignedIn_SessionKey
    while True:
        #giải mã tin nhắn
        dMsg = recveMsg(recvKey,recvSocket)
        if (dMsg == "Client disconnected"):
            break
        #tách chuỗi để xét trường hợp
        MsgArr = dMsg.split()
        # đăng ký
        if (MsgArr[0] == "signup"):
            # mã hóa trước khi cho vào cơ sở dữ liệu(Khoa code)
            
            sql = "INSERT INTO customers (name, password) VALUES (%s, %s)"
            #MsgArr[2] là mật khẩu chưa mã hóa thay bằng mật khẩu mã hóa
            val = (MsgArr[1], MsgArr[2])
            mycursor.execute(sql, val)
            mydb.commit()
            print(mycursor.rowcount, "record inserted.")
            if (mycursor.rowcount):
                SuccessMsg = ("Create new user successfully")
                sendMsg = SuccessMsg.encode()
                key = recvKey[:16].encode()
                aesEncrypt = AES.new(key,AES.MODE_CTR)
                ct_bytes = aesEncrypt.encrypt(sendMsg)
                nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
                ct = base64.b64encode(ct_bytes).decode('utf-8')
                eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()   
                recvSocket.send(eMsg)
        # đăng nhập
        elif (MsgArr[0] == "login"):
            #Mã hóa mật khẩu mới nhận được để rồi so sánh mật khẩu đang mã hóa trong csdl (Khoa code):
            # MsgArr[2] là mật khẩu chưa mã hóa. Mã hóa xong rồi nhớ thay 

            sql = "SELECT * FROM customers WHERE name = %s AND password = %s"
            val = (MsgArr[1], MsgArr[2])
            mycursor.execute(sql, val)
            myresult = mycursor.fetchall()
            if (myresult):
                SuccessMsg = ("Login successfully")
                sendMsg = SuccessMsg.encode()
                key = recvKey[:16].encode()
                aesEncrypt = AES.new(key,AES.MODE_CTR)
                ct_bytes = aesEncrypt.encrypt(sendMsg)
                nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
                ct = base64.b64encode(ct_bytes).decode('utf-8')
                eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()    
                recvSocket.send(eMsg)
                # đăng nhập xong
                clientConnected_Socket.append(recvSocket)
                clientConnected_Name.append(MsgArr[1])
                clientSignedIn_SessionKey.append(recvKey)
                for i,s in enumerate(clientConnected_Socket) :
                    # gửi danh sách socket + tên
                    sendMsg = json.dumps(clientConnected_Name).encode()
                    key = keyArr[i][:16].encode()
                    aesEncrypt = AES.new(key,AES.MODE_CTR)
                    ct_bytes = aesEncrypt.encrypt(sendMsg)
                    nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
                    ct = base64.b64encode(ct_bytes).decode('utf-8')
                    eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()    
                    s.send(eMsg)
        # thực hiện chat
        else:
            for i,name  in enumerate(clientConnected_Name):
                if (name == MsgArr[1]):
                    sendMsg = dMsg.encode()
                    key = clientConnected_SessionKey[i][:16].encode()
                    print(key)
                    aesEncrypt = AES.new(key,AES.MODE_CTR)
                    ct_bytes = aesEncrypt.encrypt(sendMsg)
                    nonce = base64.b64encode(aesEncrypt.nonce).decode('utf-8')
                    ct = base64.b64encode(ct_bytes).decode('utf-8')
                    eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()  
                    print(eMsg) 
                    clientConnected_Socket[i].send(eMsg)

if __name__ == "__main__":
    mydb = mysql.connector.connect(host='localhost',database='anm',user='anm',password='123abnkakashi',port='1998')
    mycursor = mydb.cursor()
    main() 