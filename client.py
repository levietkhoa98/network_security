import socket
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib
from Crypto.Cipher import PKCS1_OAEP

def main():
    serverAddress = "127.0.0.1"
    serverPort = 1600

    #Tạo public key và private key    
    random_generator = Random.new().read
    #Tạo key 1024 bit bởi random_generator 
    key = RSA.generate(1024,random_generator)
    #Tạo public key từ key
    public = key.publickey().exportKey(format='PEM',passphrase=None, pkcs=1)
    private = key.exportKey()
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
    decrypt = PKCS1_OAEP.new(key).decrypt(msg)
    #hashing sha1
    en_object = hashlib.sha1(decrypt)
    en_digest = en_object.hexdigest()
    print(en_digest)
    if (en_digest):
        while True:
            sendmsg = input("Insert your message")
            client.send(sendmsg.encode())
        client.close()

if __name__ == "__main__":
    main()

