---
title: '[Square CTF] Go cipher'
published: true
tags: [writeup, crypto]
author: koks
---

We are given the following encryption and decryption functions along with 5 plaintexts and 5+1 ciphertexts. One of the ciphertext files is `flag.txt.enc`.

```go
func encrypt(plaintext []byte, key []byte) string {
  x := uint64(binary.LittleEndian.Uint64(key[0:]))
  y := uint64(binary.LittleEndian.Uint64(key[8:]))
  z := uint64(binary.LittleEndian.Uint64(key[16:]))

  keyid := md5.Sum(key)
  r := keyid[:]
  for _, e := range plaintext {
    t := (e - byte(x)) ^ byte(y) ^ byte(z)
    r = append(r, t)
    x = bits.RotateLeft64(x, -1)
    y = bits.RotateLeft64(y, 1)
    z = bits.RotateLeft64(z, 1)
  }
  return hex.EncodeToString(r)
}

func decrypt(ciphertext string, key []byte) []byte {
  ciphertext_bytes, err := hex.DecodeString(string(ciphertext))
  if err != nil {
    log.Panic(err)
  }

  keyid := md5.Sum(key)
  r := keyid[:]
  if (!bytes.Equal(r, ciphertext_bytes[0:len(r)])) {
    log.Panic("invalid key")
  }
  ciphertext_bytes = ciphertext_bytes[len(keyid):]

  x := uint64(binary.LittleEndian.Uint64(key[0:]))
  y := uint64(binary.LittleEndian.Uint64(key[8:]))
  z := uint64(binary.LittleEndian.Uint64(key[16:]))

  r = make([]byte, 0, len(ciphertext_bytes))
  for _, e := range ciphertext_bytes {
    t := (e ^ byte(y) ^ byte(z)) + byte(x)
    r = append(r, t)
    x = bits.RotateLeft64(x, -1)
    y = bits.RotateLeft64(y, 1)
    z = bits.RotateLeft64(z, 1)
  }
  return r
}
```

The first 16 bytes of each ciphertext are an MD5 hash of the ID of the key that was used to encrypt it. We notice that the `flag.txt.enc` was encrypted using the same key as one of the other textfiles.

Each piece of the key is 64 bits and it's rotating by 1 bit at a time. `x` is rotating 1 bit to the right, `y` 1 bit to the left and `z` 1 bit to the left.

For simplicity, let's combine `y` and `z` into 1 variable: `yz` = `y ^ z`.

So what _rotates_ around, is doomed to come around! Every 64 bytes of the plaintext are encrypted using the same exact combination of 64-bit numbers `x` and `yz`.

We that observation we can construct a system of 3 equations and 3 unkown variables:

```
For bytes 0, 64 and 128:
=======================
ct[0] = (pt[0] - x[0]) ^ yz[0]
ct[64] = (pt[64] - x[64]) ^ yz[64]
ct[128] = (pt[128] - x[128]) ^ yz[128]

Note: 
=====
For every i in [0, 64) this holds true:

x[0 + i] == x[64 + i] == x[128 + i]
yz[0 + i] == yz[64 + i] == yz[128 + i]

and we know ct! :) 
```

We do this for every byte at index [0, 64) and feed those equations (aka constraints) into our favorite SAT solver.

We also use the knowledge/math of what are the 2 possible outcomes when a number is rotated, to add more constraints on consecutive values of `x` and `yz`:

- Right Rotation: 
	- The right-most bit goes away and a 0 comes in on the left (division by 2) 	- The right-most bit goes away and an 1 comes in on the left (division by 2 and add the value of the left-most bit) 
- Left Rotation: 
	- The left-most bit goes away and a 0 comes in on the right (multiply by 2)	- The left-most bit goes away and an 1 comes in on the right (multiply by 2 and add 1)

```python
import claripy
from binascii import unhexlify
from hashlib import md5

KEY_BITS = 64


def solve(pt, ct):
    s = claripy.Solver()
    x = [claripy.BVS("x" + str(i), 8) for i in range(KEY_BITS)]
    yz = [claripy.BVS("yz" + str(i), 8) for i in range(KEY_BITS)]

    for i in range(KEY_BITS):
        s.add(ct[0 * KEY_BITS + i] ==
              ((pt[0 * KEY_BITS + i] - x[i]) & 0xff) ^ yz[i])
        s.add(ct[1 * KEY_BITS + i] ==
              ((pt[1 * KEY_BITS + i] - x[i]) & 0xff) ^ yz[i])
        s.add(ct[2 * KEY_BITS + i] ==
              ((pt[2 * KEY_BITS + i] - x[i]) & 0xff) ^ yz[i])

        if i > 0:
            # e.g. 1010 Rotate Right by 1 bit => 0101 (/2) or 1101 (/2 + left-most Bit)
            s.add(claripy.Or(x[i] == x[i-1] >> 1, x[i]
                             == (x[i-1] >> 1) + ((0xff + 1) >> 1)))
            # e.g. 1010 Rotate Left by 1 bit => 0100 (*2 & 0xFF) or 0101 (*2 & 0xFF + 1)
            s.add(claripy.Or(yz[i] == (yz[i-1] << 1) &
                             0xff, yz[i] == ((yz[i-1] << 1) & 0xff) + 1))

    return [s.eval(xi, 1)[0] for xi in x], [s.eval(yzi, 1)[0] for yzi in yz]


if __name__ == '__main__':
    plaintext = bytearray("""Sisyphus was condemned by the gods to roll a boulder endlessly up a hill.

The joke was on them, he thought.

He was getting SUPER ripped.

-- https://twitter.com/ASmallFiction/status/1109311477570138113
""", 'utf-8')
    ciphertext = unhexlify("af2e253501ae2e2045b281dac103ece2b0d2d36ebb6ca6c023c1ecf489e819cbc08c0610afe4e45127c5c9f0cc981e6e232e585bdae502aa7c0a0d5e5f23a2d48c6717dc09a12727572158f9891d3ffe87e8db3c8951099e559798f88e5313088c83c944a85ce75b2cc97527dae0257eefd35c54daeb3bba6406106aa3596f3fa159502a0aa62b5e017d5843b2553ff880e1d451d4a7d5325d88ecf88946d0d73b8617638b5bf554272b7ef270811e67fcdf4b4a8ed509e727de4e14907bb313b37c6bf7c199e86b5478b343")

    x, yz = solve(plaintext, ciphertext)
    flag_ct = unhexlify(
        "952a25e0b1d1242e4587f9e9c119e3b7f4d3d063b9a5cdf298e2b2a4a9b42835febde85f690ca6997100351ebdb17b")

    solution = []
    for idx, c in enumerate(flag_ct):
        i = idx % KEY_BITS
        solution.append(chr(((c ^ yz[i]) + x[i]) & 0xff))
    print(''.join(solution))
```

> Yes, you did it! flag-742CF8ED6A2BF55807B14719
