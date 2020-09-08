---
title: '[ångstromCTF-2020] Noisy'
published: true
tags: [writeup, misc]
author: AltAcc
---

# Noisy Challenge Writeup

## The Challenge

### What we have
For this challenge, we were told that a message was sent in a noisy environment. The message was in Morse, and repeated a few times.

We were given the script used to send the message (with the actual message and the number of repetitions redacted):

```python
import numpy as np
from random import gauss
morse = REDACTED
repeats = REDACTED
pointed = []
for c in morse:
	if c == ".":
		pointed.extend([1 for x in range(10)])
	if c == "-":
		pointed.extend([1 for x in range(20)])
	if c == " ":
		pointed.extend([0 for x in range(20)])
	pointed.extend([0 for x in range(10)])

with open("points.txt", "w") as f:
	for _ in range(repeats):
		signal = pointed
		output = []
		for x, bit in enumerate(signal):
			output.append(bit + gauss(0,2))

		signal = list(np.array(output) - .5)
		f.write('\n'.join([str(x) for x in signal])+"\n")
f.close()
```

We were also given the file 'points.txt', which is a set of points (floats) that represent the value of the signal at a given point. The file is very long, so I won't include it here.

### What we need to do

We need to find out what was sent, ideally using the least amount of effort possible.


### The Plan

Since the gauss function was called with a mean of 0, we can assume that on average, the noise should be insignificant. 

Our plan is then as follows:

1. Average each set of 10 points into 1 value.
2. Iterate over the set of averages, progressively increasing the expected length of the plaintext with each iteration
	1. Average the values at each position of the plaintext, for each expected length of the plaintext
	2. If there are any invalid values, discard this plaintext length and move to the next
3. Print valid plaintext strings.

Note that when I say 'Average', I don't mean literally averaging stuff. The positive signal is around 0.5, and the negative signal is around -0.5. What I mean is I am creating a confidence rating about whether the value is positive or negative. The sign of the value will indicate the sign of the signal, and the magnitude of the rating will determine how confident we are than the sign is correct.

## The Solution

We begin by testing to see if our plan will work. We make a copy of the source code we're provided, and substitute in the morse code for 'TESTMESSAGE', with 15 repetitions (number chosen at random):

```python
morse = "- . ... - -- . ... ... .- --. . "
repeats = 15
```

We then write the values to a file (points.txt), and create our solution script:

```python
#!/usr/bin/env python3

import itertools,collections

# Read the file with the points
file = open('points.txt', 'r')

x = []

# Add the floats to a list
for line in file.readlines():
	x.append(line[:-1])

summs = []

# Sum up each group of 10 points
for j in range(0,len(x),10):
	sum1 = 0
	for q in range(10):
		sum1 += float(x[j + q])
	summs.append(sum1)

# Create a confidence rating about whether the signal at each position is positive or negative
def solve(solLen):

	solution = [None] * solLen
	count = 0

	def solVal(pos,val):
		if (val > 0):
			if solution[pos] == None:
				solution[pos] = 1
			else:
				solution[pos] += 1
		else:
			if solution[pos] == None:
				solution[pos] = -1
			else:
				solution[pos] -= 1

	for i in range(len(summs)):
		solVal(count,summs[i])
		count += 1
		if count == solLen:
			count = 0

	return solution

def consume(iterator, n):
	# Advance the iterator n-steps ahead. If n is none, consume entirely.
	collections.deque(itertools.islice(iterator, n), maxlen=0)

# Convert the confidence rating to Morse code
def toMorse(sol1):

	solStr = ""

	iterator = range(0, len(sol1)).__iter__()
	for i in iterator:

		if i >= len(sol1) - 1:
			solStr += '?'

		elif sol1[i] > 0:
			if sol1[i+1] > 0:
				solStr += '-'
				consume(iterator, 2)
				continue

		elif sol1[i] > 0:
			if sol1[i+1] < 0:
				solStr += '.'
				consume(iterator, 1)
				continue

		elif sol1[i] < 0:
			if sol1[i+1] < 0:
				solStr += ' '
				consume(iterator, 2)
				continue

		else:
			solStr += '?'
		solStr += "."
		consume(iterator,1)

	return solStr

def decryption(message):
	# Converts Morse code to character string.
	# Raises an exception if invalid characters are found
	#Code omitted for brevity. [Reference](https://www.geeksforgeeks.org/morse-code-translator-python/)

print("Number of samples (/10): " + str(len(summs)))

for ml in range(int(len(summs)/2)):
	try:
		sampleSol = solve(ml)
		print(decryption(toMorse(sampleSol)))
	except:
		continue
```

The script prints out "TESTMESSAGE". All we have to do now is run it against the file with the actual points we're given. The output is as follows:

	Number of samples (/10): 2880
	E A
	ANOISYNOISE
	ANOISYNOISUNOISYNOISE
	ANOISYNOISUNOISYNOISUNOISYNOISE
	ANOISYNOISUNOISYNOISUNOISYNOISUNOISYNOISE
	ANOISYNOISUNOISYNOISUNOISYNOISUNOISYNOISUNOISYNOISE
	ANOISYNOISUNOISYNOISUNOISYNOISUNOISYNOISUNOISYNOISUNOISYNOISE

The first valid string is the correct one, the rest are tainted due to the repetitions.

>Flag: ANOISYNOISE
