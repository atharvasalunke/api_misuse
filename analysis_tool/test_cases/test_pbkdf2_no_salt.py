from Crypto.Protocol.KDF import PBKDF2

password = 'mypassword'
key = PBKDF2(password, None)