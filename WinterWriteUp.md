# Winter WriteUp
*This is a solution of a crypto challenge of the DiceCTF 2024, Winter*

## Code Description

The Python code implements the WOTS and includes the following main functionalities:

- `keygen`: Generates a pair of private and public keys.
- `sign`: Signs a given message using the private key.
- `verify`: Verifies the signature of a message against the public key.

The script reads a message, signs it, and then asks for a new message and its signature. The goal is to provide a valid signature for the second message to retrieve the flag.

## Exploitation Strategy

The verification method checks if the extracted public key from the provided signature matches the generated public key. The public key components are each of the private keys hashed 256 times.

The signature consists of each of the 32 private keys hashed `256 - n` times, where `n` is the value of a byte of the message hashed with SHA-256.

To exploit this, we craft two messages, `m1` and `m2`, such that each byte in `SHA-256(m1)` is greater than `SHA-256(m2)`. Then we calculate the differences between each byte of `SHA-256(m1)` and `SHA-256(m2)`. The server provides the signature of `m1`. We divide this signature into 32 chunks and hash each chunk according to its difference. This gives us the corresponding signature of `m2`, revealing the flag.

## Script for Finding Messages

The following Python script finds two messages meeting our criteria:

```python
import hashlib
import os

def find_messages():
    count = 0
    while True:
        msg1 = os.urandom(32)
        msg2 = os.urandom(32)
        hash1 = hashlib.sha256(msg1).digest()
        hash2 = hashlib.sha256(msg2).digest()

        if all(a > b for a, b in zip(hash1, hash2)):
            print(f"Found messages after {count} attempts:")
            print(f"Message 1: {msg1.hex()}")
            print(f"Hash 1: {hash1.hex()}")
            print(f"Message 2: {msg2.hex()}")
            print(f"Hash 2: {hash2.hex()}")
            break
        count += 1
        if count % 10000 == 0:
            print(f"Checked {count} message pairs so far...")

if __name__ == '__main__':
    find_messages()
```
Our script has found two messages:
Message 1: **158b9f4c26df4898666a79e69d19f7209b2fe9efe8525b4301b352e49dca7ba0**
Hash 1:    **daa882b5ecc37b44dd6b50b2e5acb0dac0d659f5f897b05899aedcfdd2dca57c**
Message 2: **cde750320a8389a6192216bf8bae3d37cd6d94a150741724d36305dfff746bb0**
Hash 2:    **6da20d01be665436a03542585821a093539153735f7f22453fad3ba17003175c**


## Solution Script:

```python
from hashlib import sha256

def hash(x, n):
    for _ in range(n):
        x = sha256(x).digest()
    return x

sig_hex = input("Give me the signature: ")
sig_bytes = bytes.fromhex(sig_hex)
chunks = [sig_bytes[i:i+32] for i in range(0, len(sig_bytes), 32)]
diff = [109, 6, 117, 180, 46, 93, 39, 14, 61, 54, 14, 90, 141, 139, 16, 71, 109, 69, 6, 130, 153, 24, 142, 19, 90, 1, 161, 92, 98, 217, 142, 32]

sig2 = b""

for chunk, d in zip(chunks, diff):
    hashed_chunk = hash(chunk, d)
    sig2 += hashed_chunk
sig2_hex = sig2.hex()

with open('output.txt', 'w') as file:
    file.write(sig2_hex)

print("The second signature has been written to output.txt.")
``` 

Input this signature to the server to retrieve the flag: 

`dice{according_to_geeksforgeeks}`



