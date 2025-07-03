---
title: Crypto - Restricted-oracle
---

## Source
```python
from Crypto.Cipher import AES
import sys
from hashlib import sha512
import random
import os 
import secrets
import string
MAX_TRIES = lambda x: len(x)*40
TEXT_FILE = "text.txt"
def getText(n=10)->str:
    lines = []
    with open(TEXT_FILE, "r") as f:
        lines = f.readlines()
    #print(len(lines), "lines loaded from text file.")
    out = ""
    for _ in range(n):
        line =secrets.choice(lines)
        line =line.split(" ",1)[1]
        out += line.strip()
    #out = "abc"*100 + "bcd"*100+"A"
    out = "".join(filter(lambda x: x in string.ascii_letters,out))
    return out

class PadServer:
    
    def __init__(self,text):
        self.queries = [0]
        self.key =  os.urandom(16)
        self.cipher = AES.new(self.key, AES.MODE_CBC)
        self.chall = text.encode("utf-8")
        for _ in range(random.randint(0,4)):
                self.chall += chr(ord("A")+(os.urandom(1)[0] % 26)).encode()


        self.iv = os.urandom(16)
        #print(f"Padding is : {self.pad(self.chall).hex()}")
    def cutq(self):
        self.queries+=[0]
    def get_chall(self):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.iv+aes.encrypt(self.pad(self.chall))
    def pad(self, s):
        padbit = 16 - len(s) % 16
        padding = bytes([padbit] * padbit)
        return s + padding
    def unpad(self, s):
        padbit = s[-1]
        padding = s[-padbit:]
        if set(padding) == {padbit}:
            return s[:-s[-1]]
        else:
            return None
    def decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plaintext = cipher.decrypt(ciphertext)

        return plaintext

    def oracle(self, ciphertext):
        self.queries[-1] += 1
        plaintext = self.decrypt(ciphertext)
        #print("oracle request decrypts to ", plaintext.hex())
        if self.unpad(plaintext) == None:
            return False
        else:
            return True

def getFlag():
    with open("/flag", "r") as f:
        return f.read().strip()
def xor(a:bytes,b:bytes)->bytes:

    ml  = max(len(a),len(b))
    a = a.ljust(ml, b'\x00')
    b = b.ljust(ml, b'\x00')
    return bytes(x ^ y for x, y in zip(a, b))

if __name__ == "__main__":
    print("Welcome to the Pad Server!")
    FLAG =getFlag()
    text =getText()
    oracle =PadServer(text)
    MAX_TRIES = MAX_TRIES(text)
    tries = 0
    print(xor(sha512(text[:-3].encode("utf-8")).digest(),FLAG.encode()).hex())

    print(oracle.get_chall().hex())
    while tries < MAX_TRIES:
        ciph = bytes.fromhex(input("speak to the oracle: "))
        if len(ciph) % 16 != 0:
            print("Ciphertext must be a multiple of 16 bytes.")
            continue
        print("Oracle says: ", oracle.oracle(ciph))
        tries+=1
```

## Ý tưởng
Dạng bài này tương tự với bài "Pad Thai" bên CryptoHack, với cơ chế lợi dụng hàm check valid padding PKCS7 \
```python
    def oracle(self, ciphertext):
        self.queries[-1] += 1
        plaintext = self.decrypt(ciphertext)
        #print("oracle request decrypts to ", plaintext.hex())
        if self.unpad(plaintext) == None:
            return False
        else:
            return True
```
Để làm rõ hơn về ý tưởng, ta hãy bắt đầu tư cơ chế mã hóa của AES-CBC:  
- AES-CBC chia plaintext thành các khối 16 bytes. Khối đầu tiên sẽ xor với iv (key dùng 1 lần), rồi đem đi mã hóa aes, kết quả ta có được 1 block ciphertext. Sau đó đem block ciphertext đó xor với khối plaintext thứ 2, tiếp diễn như vậy đến khi hết 
- Đối với bài này, vì chương trình chỉ check padding valid chứ không phải là giải mã ciphertext được ra bảng ascii, nên ta có thể tấn công bằng cách: 
    + B1: Đặt iv làm block ciphertext đầu tiên, khối ciphertext đầu tiên thành khối thứ 2 tạo thành 1 cụm ciphertext 
    + B2: Giả sử ta cần có padding "/x01", ta sẽ thay đổi byte cuối của iv (hiện đang làm block ciphertext số 1) sao cho chương trình báo về True. 
    + B3: Khi báo True, lấy byte bruteforce đó xor với iv_fake sẽ tương đương với plaintext xor với iv gốc ở byte đó. Vậy ta đã khôi phục được 1 kí tự
    + Làm lần lượt với các kí tự còn lại và các block ciphertext còn lại

Với ý tưởng như vậy, vứt lên chatgpt để nó gen ra câu trả lời: \
```python
import string

# Define the likely character set at the top of your script
POSSIBLE_CHARS = string.ascii_letters # a-z, A-Z

# ... inside the main attack loop ...

# Decrypt byte by byte, from last to first
for byte_index in range(15, -1, -1):
    padding_val = 16 - byte_index
    forged_manip_suffix = b''
    for i_byte in intermediate_bytes:
        forged_manip_suffix += bytes([i_byte ^ padding_val])

    found = False
    
    # --- OPTIMIZATION START ---
    # 1. First, try guessing based on the known character set
    for p_char in POSSIBLE_CHARS:
        # Calculate the one guess that would produce this character
        p_byte = ord(p_char)
        guess = p_byte ^ padding_val ^ manipulation_block[byte_index]
        
        forged_manip_block = b'\x00' * byte_index + bytes([guess]) + forged_manip_suffix
        payload = forged_manip_block + target_block

        if get_oracle_response(payload):
            intermediate_byte = guess ^ padding_val
            plaintext_byte = intermediate_byte ^ manipulation_block[byte_index]
            
            intermediate_bytes = bytes([intermediate_byte]) + intermediate_bytes
            decrypted_block_plaintext = bytes([plaintext_byte]) + decrypted_block_plaintext
            
            log.success(f"Found byte {15-byte_index}/16 (fast): {hex(plaintext_byte)} ('{chr(plaintext_byte)}')")
            found = True
            break
            
    if found:
        continue # Move to the next byte_index
    
    # 2. If the fast method failed, fall back to the full brute-force
    #    (This will find the padding bytes)
    log.info(f"Optimized search failed for byte {15-byte_index}/16. Falling back to full scan...")
    for guess in range(256):
        # Prevent re-testing guesses we already tried in the optimized loop
        # This is a micro-optimization and can be skipped for simplicity
        p_byte_from_guess = (guess ^ padding_val) ^ manipulation_block[byte_index]
        if chr(p_byte_from_guess) in POSSIBLE_CHARS:
            continue

        forged_manip_block = b'\x00' * byte_index + bytes([guess]) + forged_manip_suffix
        payload = forged_manip_block + target_block

        if get_oracle_response(payload):
            intermediate_byte = guess ^ padding_val
            plaintext_byte = intermediate_byte ^ manipulation_block[byte_index]
            
            intermediate_bytes = bytes([intermediate_byte]) + intermediate_bytes
            decrypted_block_plaintext = bytes([plaintext_byte]) + decrypted_block_plaintext
            
            log.success(f"Found byte {15-byte_index}/16 (full): {hex(plaintext_byte)}")
            found = True
            break
    # --- OPTIMIZATION END ---
            
    if not found:
        log.error("Failed to find byte even with full scan.")
        exit()
```
