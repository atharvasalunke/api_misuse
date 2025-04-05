from Crypto.Cipher import AES

hardcoded_key = b'secretkey'
cipher = AES.new(hardcoded_key, AES.MODE_CBC, b'1234567812345678')