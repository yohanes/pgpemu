import zlib
import sys
from Crypto.Cipher import AES
import Crypto.Cipher.AES
import struct

key = 'ea1dd700959376289e859679703130fe'
IV = '65b97980c63e1d5dd1eae221fa19c98b'

x = AES.new(key.decode("hex"),AES.MODE_CBC,IV.decode("hex"))

with open("pogoplus.bin", "rb") as f:
    orig = f.read()

with open(sys.argv[1], "rb") as f:
    plain = f.read()


enc = x.encrypt(plain)

oldheader  = orig[0x8000:0x8000+64]

header = oldheader[:8]

crc = struct.pack("I", zlib.crc32(plain)&0xffffffff)

header += crc 

header += oldheader[8+4:]

body= header + enc

result = orig[:0x8000] + body + orig[0x8000+len(body):]

with open("result.bin", "wb") as f:
    f.write(result)
