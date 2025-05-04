from Crypto.Cipher import AES

def start():
    key = b"1234567890123456"
    secure_encrypt(key)

def secure_encrypt(k):
    AES.new(k, AES.MODE_ECB)