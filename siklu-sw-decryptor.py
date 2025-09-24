# siklu-sw-decryptor.py
#!/usr/bin/env python3

from Crypto.Cipher import AES
import hashlib
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <encrypted_file> [output_file]")
    sys.exit(1)

print(f"[*] Reading encrypted file: {sys.argv[1]}")
with open(sys.argv[1], 'rb') as f:
    data = f.read()
print(f"[+] File size: {len(data)} bytes")


footer = data[-32:]
encrypted = data[:-32]
print(f"[*] Extracted 32-byte footer")
print(f"    Footer: {footer.hex()}")


if encrypted[:8] != b'Salted__':
    print("[!] Error: Missing OpenSSL salt header")
    sys.exit(1)

salt = encrypted[8:16]
ciphertext = encrypted[16:]
print(f"[+] Found OpenSSL header with salt: {salt.hex()}")

static = bytes([0x08,0x30,0x64,0xd1,0x3a,0xe7,0x44,0xc8,0x94,0x64,0x23,0x01,0x77,0xfb,0x90,0x77])
password = static + footer[:16]
print(f"[*] Building 32-byte password")
print(f"    Static part:  {static.hex()}")
print(f"    Dynamic part: {footer[:16].hex()}")

print(f"[*] Deriving AES-256-CBC key using EVP_BytesToKey")
m1 = hashlib.md5(password + salt).digest()
m2 = hashlib.md5(m1 + password + salt).digest()
m3 = hashlib.md5(m2 + password + salt).digest()

key = m1 + m2  
iv = m3[:16]
print(f"    Key: {key.hex()}")
print(f"    IV:  {iv.hex()}")


if len(ciphertext) % 16 != 0:
    pad_needed = 16 - (len(ciphertext) % 16)
    print(f"[*] Padding ciphertext with {pad_needed} zero bytes")
    ciphertext += b'\x00' * pad_needed


print(f"[*] Decrypting {len(ciphertext)} bytes with AES-256-CBC")
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)


pad = plaintext[-1]
if 1 <= pad <= 16 and all(b == pad for b in plaintext[-pad:]):
    print(f"[*] Removing PKCS7 padding ({pad} bytes)")
    plaintext = plaintext[:-pad]

output_file = sys.argv[2] if len(sys.argv) > 2 else 'siklu-decrypted.bin'
with open(output_file, 'wb') as f:
    f.write(plaintext)

if plaintext[:4] == b'\x27\x05\x19\x56':
    print(f"[*] Successfully decrypted to {output_file}")
    print(f"    Output size: {len(plaintext)} bytes")
    print(f"    Magic: 0x{plaintext[:4].hex().upper()} (U-Boot image)")
else:
    print(f"Decryption failed: 0x{plaintext[:4].hex().upper()}")
