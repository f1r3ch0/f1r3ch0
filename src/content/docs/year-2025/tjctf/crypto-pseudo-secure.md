---
title: Crypto - Pseudo-Random
---

# Crypto - Pseudo-Random

## Challenge
```python
#!/usr/local/bin/python
import random
import base64
import sys
import select

class User:
    def __init__(self, username):
        self.username = username
        self.key = self.get_key()
        self.message = None

    def get_key(self):
        username = self.username
        num_bits = 8 * len(username)
        rand = random.getrandbits(num_bits)
        rand_bits = bin(rand)[2:].zfill(num_bits)
        username_bits = ''.join([bin(ord(char))[2:].zfill(8) for char in username])
        xor_bits = ''.join([str(int(rand_bits[i]) ^ int(username_bits[i])) for i in range(num_bits)])
        xor_result = int(xor_bits, 2)
        shifted = ((xor_result << 3) & (1 << (num_bits + 3)) - 1) ^ 0x5A
        byte_data = shifted.to_bytes((shifted.bit_length() + 7) // 8, 'big')
        key = base64.b64encode(byte_data).decode('utf-8')
        return key
    
    def set_message(self, message):
        self.message = message

def input_with_timeout(prompt="", timeout=10):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.buffer.readline().rstrip(b'\n')
    raise Exception
input = input_with_timeout

flag = open("flag.txt").read()

assert len(flag)%3 == 0
flag_part1 = flag[:len(flag)//3]
flag_part2 = flag[len(flag)//3:2*len(flag)//3]
flag_part3= flag[2*len(flag)//3:]

admin1 = User("Admin001")
admin2 = User("Admin002")
admin3 = User("Admin003")
admin1.set_message(flag_part1)
admin2.set_message(flag_part2)
admin3.set_message(flag_part3)
user_dict = {
    "Admin001": admin1,
    "Admin002": admin2,
    "Admin003": admin3
}

print("Welcome!")
logged_in = None
user_count = 3 
MAX_USERS = 200

while True:
    if logged_in is None:
        print("\n\n[1] Sign-In\n[2] Create Account\n[Q] Quit")
        inp = input().decode('utf-8').strip().lower()
        match inp:
            case "1":
                username = input("Enter your username:  ").decode('utf-8')
                if username in user_dict:
                    user = user_dict[username]
                    key = input("Enter your sign-in key: ").decode('utf-8')
                    if key == user.key:
                        logged_in = user
                        print(f"Logged in as {username}")
                    else:
                        print("Incorrect key. Please try again!")
                else:
                    print("Username not found. Please try again or create an account.")
            case "2":
                if user_count >= MAX_USERS:
                    print("Max number of users reached. Cannot create new account.")
                else:
                    username = input("Select username:  ").decode('utf-8')
                    if username in user_dict:
                        print(f"Username '{username}' is already taken!")
                    else:
                        user_dict[username] = User(username)
                        user_count += 1 
                        print(f"Account successfully created!\nYour sign-in key is: {user_dict[username].key}")
            case "q":
                sys.exit()
            case _:
                print("Invalid option. Please try again.")
    else:
        print(f"Welcome, {logged_in.username}!")
        print("\n\n[1] View Message\n[2] Set Message\n[L] Logout")
        inp = input().decode('utf-8').strip().lower()
        match inp:
            case "1":
                print(f"Your message: {logged_in.message}")
            case "2":
                new_message = input("Enter your new message: ").decode('utf-8')
                logged_in.set_message(new_message)
                print("Message updated successfully.")
            case "l":
                print(f"Logged out from {logged_in.username}.")
                logged_in = None
            case _:
                print("Invalid option. Please try again.")
```

Đề bài chia flag thành 3 phần, sau đó tạo ra 3 tài khoản admin001->3, tạo key "ngẫu nhiên" rồi đẩy flag vào message của các tài khoản đó.

## Solvation
Key được tạo bởi hàm get_key() dựa vào 2 yếu tố là độ dài của username và module ```random```. Nếu ở trạng thái mặc định, PRNG của module dựa trên thuật toán Mersenne Twister (MT19937-64). Thuật toán này không còn an toàn trong việc mã hóa khi mà nếu biết trước được 624 số 32-bit được tạo ra liên tiếp, ta có thể biết trước được số tiếp theo hoặc số trước 624 số 32-bit đó.  

Trong bài này, ta sẽ sử dụng module ```randcrack``` để dự đoán số. Để module có thể hoạt động chính xác, ta cần nạp đủ 624 số. Bằng việc đảo ngược hàm get_key(), ta có thể lấy được số giả ngẫu nhiên mà module ```random``` sinh ra. Nhưng ta không thể để chương trình tạo luôn các số 32-bit vì có giới hạn trong việc tạo các tài khoản (MAX_USER = 200 - 3 tài khoản admin). 

Đào sâu thêm về PRNG của module ```random```, ta thấy rằng các số có kích thước > 32-bit đều được tạo bởi các số 32-bit ghép vào nhau. Ví dụ: Để tạo 1 số 64 bit ta có:
```python
random.getrandbits(64) = (random.getrandbits(32) & 0xFFFFFFFF) | (random.getrandbits(32) << 32)
```
Vậy việc nạp 624 số 32-bit = 312 số 64-bit = 156 số 128-bit < giới hạn là 197

Các bước làm là: \
B1: Tạo 156 username có độ dài 16 kí tự \
B2: Nạp vào server để chương trình tạo key tương ứng \
B3: Trích xuất key từ chương trình, đảo ngược quá trình sinh key để lấy ra được các số giả ngẫu nhiên 128-bit \
B4: Tách số 128-bit thành các số 32-bit, nạp vào module ```randcrack```, sau đó lùi 624 + 6 số vì 3 tài khoản được tạo bởi số giả ngẫu nhiên có kích thước 8 * 8 = 64-bit. \
B5: Để module dự đoán 3 số 64-bit của 3 tài khoản admin, tính toán key rồi đẩy lên server để lấy flag 

## Script
```python
from pwn import *
from randcrack import RandCrack
import base64
import string

accept_character = string.ascii_letters + string.digits
random_number = []

rc = RandCrack()
def guess_the_future_and_past(random_number : list): #in this case is 128-bit number
    for rannum in random_number:
        low3_guess = (rannum >> 96) & 0xFFFFFFFF
        low2_guess = (rannum >> 64) & 0xFFFFFFFF
        low1_guess = (rannum >> 32) & 0xFFFFFFFF
        low0_guess = rannum & 0xFFFFFFFF
        rc.submit(low0_guess)
        rc.submit(low1_guess)
        rc.submit(low2_guess)
        rc.submit(low3_guess)
    rc.offset(-624)
    rc.offset(-6)
    return [(rc.predict_getrandbits(32) & 0xFFFFFFFF) | (rc.predict_getrandbits(32) << 32) for _ in range(3)]

def recover_rand_from_key(username: str, key: str) -> int:
    shifted_bytes = base64.b64decode(key)
    shifted_int   = int.from_bytes(shifted_bytes, 'big')
    masked_shift  = shifted_int ^ 0x5A
    xor_result    = masked_shift >> 3
    num_bits      = 8 * len(username)
    username_bits = int(''.join(format(ord(c), '08b') for c in username),2)
    rand = xor_result ^ username_bits
    rand &= (1 << num_bits) - 1
    return rand

def get_key(username : str, rand : int, num_bits : int) -> str:
    rand_bits       = bin(rand)[2:].zfill(num_bits)
    username_bits   = ''.join([bin(ord(char))[2:].zfill(8) for char in username])
    xor_bits        = ''.join([str(int(rand_bits[i]) ^ int(username_bits[i])) for i in range(num_bits)])
    xor_result      = int(xor_bits, 2)
    shifted         = ((xor_result << 3) & (1 << (num_bits + 3)) - 1) ^ 0x5A
    byte_data       = shifted.to_bytes((shifted.bit_length() + 7) // 8, 'big')
    key             = base64.b64encode(byte_data).decode('utf-8')
    return key

def connect_to_solve(host, port):
    admin = {}
    conn = remote(host, port)
    print(conn.recvuntil(b"Quit").decode())
    for _ in range(156):    
        conn.sendline("2".encode())
        print(conn.recvline().decode())
        username = random.choices(accept_character, k = 16)
        conn.sendline(''.join(username).encode())
        output = conn.recvuntil(b"Quit").decode()
        print(output)
        key = output.split("\n")[1].split(": ")[1]
        rand_number = recover_rand_from_key(username, key)
        random_number.append(rand_number)
        print(rand_number)
    admin_guess = guess_the_future_and_past(random_number)
    
    for i in range(3):
        admin[f"Admin00{i + 1}"] = get_key(f"Admin00{i + 1}", admin_guess[i], 64)
        conn.sendline(b'1')
        print(conn.recvuntil(b"username: "))
        conn.sendline(f"Admin00{i + 1}".encode())
        print(conn.recvuntil(b"key: ").decode())
        conn.sendline(str(admin[f"Admin00{i + 1}"]).encode())
        print(str(admin[f"Admin00{i + 1}"]))
        print(conn.recvuntil(b"Logout").decode())
        conn.sendline(b'1')
        print(conn.recvuntil(b"Logout").decode())
        conn.sendline(b'L')

if __name__ == "__main__":
    host = "tjc.tf"
    port = 31400
    connect_to_solve(host, port)
```
