import socket
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib
from Crypto.Cipher import PKCS1_OAEP
import threading
from base64 import b64encode
import base64
import json
import time
from tkinter import *
import queue
from functools import partial

msgQueue = queue.Queue()

def sendeMsg(key,client,message):
    sendMsg = message.encode()
    # print(sendMsg)
    key = key[:16].encode()
    # print(key)
    aesEncrypt = AES.new(key,AES.MODE_CTR)
    # print(aesEncrypt)
    ct_bytes = aesEncrypt.encrypt(sendMsg)
    nonce = b64encode(aesEncrypt.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()
    # print(eMsg)
    client.send(eMsg)

def recvdMsg(key,client,msgQueue):
    eMsg = client.recv(1024).decode()
    b64 = json.loads(eMsg)
    nonce = base64.b64decode(b64['nonce'])
    ct = base64.b64decode(b64['ciphertext'])
    # print(eMsg)
    key = key[:16].encode()
    # print(key)
    aesDecrypt = AES.new(key,AES.MODE_CTR,nonce=nonce)
    # print(aesDecrypt)
    dMsg = aesDecrypt.decrypt(ct).decode()
    print("New mess from client ",client ," : " , dMsg)
    if (dMsg == "Create new user successfully" or dMsg == "Login successfully" or (dMsg.startswith('[') and dMsg.endswith(']'))):
        msgQueue.put(dMsg)

def Signup(key,client):
	global pwordE
	global nameE

	global roots

	roots = Tk()
	roots.title('Signup')
	instruction = Label(roots, text='register')
	instruction.grid(row=0, column=0, sticky=E)

	nameL = Label(roots, text='New Username: ')
	pwordL = Label(roots,text='New Password: ')
	nameL.grid(row=1, column=0, sticky=W)
	pwordL.grid(row=2, column=0, sticky=W)

	nameE = Entry(roots)
	pwordE = Entry(roots, show='*')
	nameE.grid(row=1, column=1)
	pwordE.grid(row=2, column=1)

	signupButton = Button(roots, text='Signup', command=partial(FSSignup,key,client))
	signupButton.grid(columnspan=2, sticky=W)
	roots.mainloop()

def FSSignup(key,client):
    print(msgQueue.empty())
    sendMsg = "signup " + nameE.get() + " " + pwordE.get()
    threadSend = threading.Thread(target=sendeMsg,args=(key,client,sendMsg,))
    threadSend.start()
    threadSend.join()

    threadRecv = threading.Thread(target=recvdMsg,args=(key,client,msgQueue,))
    threadRecv.start()
    threadRecv.join()

    if ( msgQueue.get() == "Create new user successfully" ):
        roots.destroy()
        print(msgQueue.empty())
        Login(key,client)

def Login(key,client):
	global nameEL
	global pwordEL
	global rootA

	rootA = Tk()
	rootA.title('Login')

	instruction = Label(rootA, text='Login\n')
	instruction.grid(sticky=E)

	nameL = Label(rootA, text='Username: ')
	pwordL = Label(rootA, text='Password: ')
	nameL.grid(row=1, sticky=W)
	pwordL.grid(row=2, sticky=W)

	nameEL = Entry(rootA)
	pwordEL = Entry(rootA, show='*')
	nameEL.grid(row=1, column=1)
	pwordEL.grid(row=2, column=1)

	loginB = Button(rootA, text='submit', command=partial(CheckLogin,key,client))
	loginB.grid(columnspan=2, sticky=W)

	rmuser = Button(rootA, text='register', fg='red', command=partial(DelUser,key,client))
	rmuser.grid(columnspan=2, sticky=W)
	rootA.mainloop()

def CheckLogin(key,client):
    print(msgQueue.empty())
    sendMsg = "login " + nameEL.get() + " " + pwordEL.get()
    threadSend = threading.Thread(target=sendeMsg,args=(key,client,sendMsg,))
    threadSend.start()
    threadSend.join()

    threadRecv = threading.Thread(target=recvdMsg,args=(key,client,msgQueue,))
    threadRecv.start()
    threadRecv.join()
    if ( msgQueue.get() == "Login successfully" ):
        threadRecv = threading.Thread(target=recvdMsg,args=(key,client,msgQueue,))
        threadRecv.start()
        threadRecv.join()

        print(msgQueue.empty())
        rootA.destroy()
        data = msgQueue.get()
        chat(key,client,data)
    else:
        r = Tk()	
        r.title('D:')
        r.geometry('150x50')
        rlbl = Label(r, text='\n[! Invalid Login')
        rlbl.pack()
        r.mainloop()	

def DelUser(key,client):
	rootA.destroy()
	Signup(key,client)

def chat(key,client,data):
	global rootsC

	rootsC = Tk()
	rootsC.title('chat')
	instruction = Label(rootsC, text='chat' )
	instruction.grid(row=0, column=0, sticky=E)
	for i,name in enumerate(data):
		x=i+2
		btn_row = Button(rootsC, text=name)
		btn_row.grid(row=x)

	
	
	userName=Label(rootsC,text='hoang',width = 20)

	userName.grid(row =5 , column=0)

	chatBox=Label(rootsC,width = 40 , height = 20 , bd =1 , relief='solid')
	chatBox.grid(row=6 , column =0)
	chatF=Entry(rootsC , width = 33)
	chatF.grid(columnspan=2 ,row=7, column=0, sticky=W )
	addButton1 = Button(rootsC, text='send', command='', width=10)
	addButton1.grid(columnspan=2, row=7, column=0, sticky=E)

	rootsC.mainloop()

def main():
    serverAddress = "127.0.0.1"
    # serverAddress = "192.168.1.1"
    serverPort = 1600

    #Tạo public key và private key    
    random_generator = Random.new().read
    #Tạo key 1024 bit bởi random_generator 
    key = RSA.generate(1024,random_generator)
    #Tạo public key từ key
    public = key.publickey().exportKey(format='PEM',passphrase=None, pkcs=1)
    #hash public key 
    hash_object = hashlib.sha1(public)
    hex_digest = hash_object.hexdigest()
    
    #kết nối đến server
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.connect((serverAddress,serverPort))
    print("Connectd to sever")
    client.send(public)
    confirm = client.recv(1024)
    if confirm.decode() == "YES":
        client.send(hex_digest.encode())
    #connected msg
    msg = client.recv(1024)
    # dùng private key để giải mã lấy session key 
    decrypt = PKCS1_OAEP.new(key).decrypt(msg)
    #hashing sha1
    en_object = hashlib.sha1(decrypt)
    en_digest = en_object.hexdigest()
    print(en_digest)
    if (en_digest):
        Login(en_digest,client)
        while True:            
            print(threading.active_count())
        client.close()

if __name__ == "__main__":
    main()

