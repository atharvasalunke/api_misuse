from Crypto.Protocol.KDF import PBKDF2

salt = b'hardcodedsalt123'
key = PBKDF2('mypassword', salt)