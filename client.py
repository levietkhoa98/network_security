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
CurrentChatUsr = ""
x = 0 
y = 0
#hàm gửi tin nhắn mã hóa
def sendeMsg(key,client,message):
    sendMsg = message.encode()
    key = key[:16].encode()
    aesEncrypt = AES.new(key,AES.MODE_CTR)
    ct_bytes = aesEncrypt.encrypt(sendMsg)
    nonce = b64encode(aesEncrypt.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    eMsg = json.dumps({'nonce':nonce, 'ciphertext':ct}).encode()
    client.send(eMsg)

#hàm nhận tin nhắn mã hóa chạy để chat trong function chat và hiển thị tin nhắn mình nhận được
def recvdMsgTTK(key,client):
    key = key[:16].encode()
    while True:
        global x
        global y
        global CurrentChatUsr
        global count
        eMsg = client.recv(1024).decode()
        b64 = json.loads(eMsg)
        nonce = base64.b64decode(b64['nonce'])
        ct = base64.b64decode(b64['ciphertext'])
        aesDecrypt = AES.new(key,AES.MODE_CTR,nonce=nonce)
        dMsg = aesDecrypt.decrypt(ct).decode()
        print("New mess from client ",client ," : " , dMsg)
        if (dMsg == "Create new user successfully" or dMsg == "Login successfully" or (dMsg.startswith('[') and dMsg.endswith(']'))):
            msgQueue.put(dMsg)
            data = msgQueue.get().split(',')
            CreateListUsr(listbox_2,data)
        else :
            MsgArr = dMsg.split()
            chatMsg=""
            if (myName == MsgArr[1] and CurrentChatUsr == MsgArr[0]):
                for i,m in enumerate(MsgArr):
                    if (i>1):
                        chatMsg = chatMsg + MsgArr[i] + " "
                displayMsg = CurrentChatUsr + ": " + chatMsg + "\n"
                position = str(x) + "." + str(y)
                chatBox.insert(position,displayMsg)
                x = x + 1

#hàm nhận tin nhắn mã hóa chạy để check đăng nhập, đăng ký 
def recvdMsg(key,client,msgQueue):
    global x
    global y
    global CurrentChatUsr
    global count
    eMsg = client.recv(1024).decode()
    b64 = json.loads(eMsg)
    nonce = base64.b64decode(b64['nonce'])
    ct = base64.b64decode(b64['ciphertext'])
    key = key[:16].encode()
    print(key)
    aesDecrypt = AES.new(key,AES.MODE_CTR,nonce=nonce)
    dMsg = aesDecrypt.decrypt(ct).decode()
    print("New mess from client ",client ," : " , dMsg)
    if (dMsg == "Create new user successfully" or dMsg == "Login successfully" or (dMsg.startswith('[') and dMsg.endswith(']'))):
        msgQueue.put(dMsg)

#Khung đăng ký
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

#hàm để thực hiện đăng ký
def FSSignup(key,client):
    sendMsg = "signup " + nameE.get() + " " + pwordE.get()
    threadSend = threading.Thread(target=sendeMsg,args=(key,client,sendMsg,))
    threadSend.start()
    threadSend.join()

    threadRecv = threading.Thread(target=recvdMsg,args=(key,client,msgQueue,))
    threadRecv.start()
    threadRecv.join()

    if ( msgQueue.get() == "Create new user successfully" ):
        roots.destroy()
        Login(key,client)

#khung đăng nhập
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

#Hàm để thực hiện đăng nhập
def CheckLogin(key,client):
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

        global myName
        myName = nameEL.get()

        rootA.destroy()
        data = msgQueue.get().split(',')
        chat(key,client,data)
    else:
        r = Tk()	
        r.title('D:')
        r.geometry('150x50')
        rlbl = Label(r, text='\n[! Invalid Login')
        rlbl.pack()
        r.mainloop()	

#hàm chuyển đổi khung đăng ký đăng nhập
def DelUser(key,client):
	rootA.destroy()
	Signup(key,client)

#khung chat chính
def chat(key,client,data):
    global rootsC

    rootsC = Tk()
    rootsC.title('chat')

    searchButton= Button(rootsC, text='search', command='', width=10 , justify=LEFT)
    entry_1 = Entry(rootsC) 
    scrollbar_1 = Scrollbar(rootsC)
    global listbox_2
    listbox_2 = Listbox(rootsC, yscrollcommand=scrollbar_1.set, selectmode=SINGLE)
    # danh sách người dùng đang đăng nhập
    CreateListUsr(listbox_2,data)
    
    scrollbar_1.config(command=listbox_2.yview)

    entry_1.grid(row=0, column=6)
    searchButton.grid(row=0,column=7)

    listbox_2.grid(rowspan=4, columnspan=4, row=2, column=0)
    scrollbar_1.grid(rowspan=4, row=2, column=4, sticky=N+S)
    # phần hiển thị tin nhắn
    global chatBox
    chatBox=Text(rootsC,width = 40 , height = 20 , bd =2 , relief='solid')
    chatBox.grid(row=5, column =6)
    global CurrentChatUsr
    global x
    global y
    CurrentChatUsr = ""
    x = 0
    y = 0
    #phần nhập tin nhắn
    chatF=Entry(rootsC , font = ('courier', 15, 'bold'),width = 23)
    chatF.grid(rowspan=2,row=6, column=6, sticky=W )
    # nút gửi tin nhắn
    addButton1 = Button(rootsC, text='send', command=partial(MsgChat,key,client,chatF,chatBox,listbox_2), width=10)
    addButton1.grid(columnspan=2, row=7, column=6, sticky=E)
    #nút thêm file để gửi (Quý code)
    addButton2= Button(rootsC, text='add', command='', width=10)
    addButton2.grid(columnspan=2, row=8, column=6, sticky=E)

    threading.Thread(target=recvdMsgTTK,args=(key,client)).start()        
    rootsC.after(2000, checSelectkUser, listbox_2)

    rootsC.mainloop()

#hàm kiểm tra người dùng đang chat hiện tại là ai
def checSelectkUser(listbox):
    global CurrentChatUsr
    global x
    global y
    if (listbox.get(ACTIVE)) :
        if (CurrentChatUsr == ""):
            CurrentChatUsr = listbox.get(ACTIVE)
            x = 1
            y = 0
        else:
            if (CurrentChatUsr != listbox.get(ACTIVE)):
                chatBox.delete("1.0",END)
                x = 1
    rootsC.after(2000, checSelectkUser, listbox_2)

#hàm cập nhập danh sách người dùng đang onl
def CreateListUsr(listbox,data):
    listbox.delete(0,END)
    for i,name in enumerate(data):
        if (replaceUsrname(name) != myName):
            clientNum = "client_" + str(i)
            clientNum = StringVar(rootsC, name=replaceUsrname(name))
            #configuration
            listbox.insert(i, clientNum)

#hàm hiển thị lên khung chat tin nhắn mình gửi
def MsgChat(key,client,message,chatBox,listbox):
    global CurrentChatUsr
    global x
    global y
    if (listbox.get(ACTIVE)) :
        if (CurrentChatUsr == ""):
            CurrentChatUsr = listbox.get(ACTIVE)
            x = 1
            y = 0
        else:
            if (CurrentChatUsr != listbox.get(ACTIVE)):
                chatBox.delete("1.0",END)
                x = 1
    recvName = CurrentChatUsr
    sendMsg = myName + " " + recvName + " " + message.get()
    sendeMsg(key,client,sendMsg)
    displayMsg = myName + ": " + message.get() + "\n"
    position = str(x) + "." + str(y)
    chatBox.insert(position,displayMsg)
    x = x + 1

#hàm xử lý tên
def replaceUsrname(data):
    data = data.replace('[','').replace('"','').replace(']','').replace(' ','')
    return data

#hàm main thực hiện kết nối trao đổi khóa
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
        client.close()

if __name__ == "__main__":
    main()

