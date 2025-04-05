from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

salt = get_random_bytes(16)
key = PBKDF2('mypassword', salt)