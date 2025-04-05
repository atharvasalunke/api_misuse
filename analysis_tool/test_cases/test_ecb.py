from Crypto.Cipher import AES

key = b'mysecrethardcodedkey123'
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(b'Attack at dawn!')