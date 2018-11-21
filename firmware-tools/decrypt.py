from Crypto.Cipher import AES
import Crypto.Cipher.AES

key = 'ea1dd700959376289e859679703130fe'
IV = '65b97980c63e1d5dd1eae221fa19c98b'

x = AES.new(key.decode("hex"),AES.MODE_CBC,IV.decode("hex"))

with open("pogoplus.bin", "rb") as f:
    data = f.read()

size = 31984

plaintext = x.decrypt(data[0x8000+64:0x8000+64+size])

with open("dec.bin", "wb") as f:
    f.write(plaintext)
