from Crypto.Cipher import AES

key = b'mykey12345678901'
cipher = AES.new(key, AES.MODE_CBC)