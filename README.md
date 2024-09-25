# CTF_TryOut
Writeup on Hackthebox CTF - Should prob improve instead of readme.txt files for writeups (https://themes.gohugo.io/themes/hugo-theme-hello-friend-ng/)

# MISC
## Character
*Security through Induced Boredom is a personal favourite approach of mine. Not as exciting as something like The Fray, but I love making it as tedious as possible to see my secrets, so you can only get one character at a time!*

Connecting using 'nc IP PORT' given by the exercise. I am able to see a game where I can give the server an index number and it will return the character at a specific index of the flag. This challengde could be sovled manually, but obviously should be solved using a script. 

First I made a script that iterates over each int in the range 0-103. This took all the answers and printed them into a .txt file.
```
import socket

def main():
    # Define the target IP and port
    ip = '83.136.254.11'
    port = 34163
    output = []

    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        
        # Loop through the range 0-103
        for number in range(104):
            # Send the number as bytes (with a newline character)
            message = f"{number}\n"
            s.sendall(message.encode())
            
            # Receive response
            response = s.recv(4096)  # Adjust buffer size as needed
            
            # Decode and append the response to the output list
            output.append(response.decode().strip())

    # Join the output list into a single string
    combined_output = "\n".join(output)
    
    # Save to a file
    with open("output.txt", "w") as f:
        f.write(combined_output)

if __name__ == "__main__":
    main()
```


The output is unfiltered and contains a lot of noise. Therefore I created a parser that would remove the noise:

```def extract_characters(input_file, output_file):
    with open(input_file, 'r') as file:
        lines = file.readlines()
    
    # Initialize an empty list to store the characters
    characters = []

    # Process each line to extract characters after the ":"
    for line in lines:
        # Split the line at the colon and get the second part, stripping whitespace
        if ':' in line:
            character = line.split(':')[1].strip()  # Get the character after the colon
            characters.append(character)

    # Join all characters to form the final string
    final_string = ''.join(characters)

    # Save the final string to the output file
    with open(output_file, 'w') as file:
        file.write(final_string)

if __name__ == "__main__":
    input_file = "output.txt"  # Name of the input file containing the output
    output_file = "final_flag.txt"  # Name of the output file for the final result
    extract_characters(input_file, output_file)
```

final_flag.txt revealed the flag as ***HTB{tH15_1s_4_r3aLly_l0nG_fL4g_i_h0p3_f0r_y0Ur_s4k3_tH4t_y0U_sCr1pTEd_tH1s_oR_els3_iT_t0oK_qU1t3_l0ng!!}***

## Stop Drop and Roll
*The Fray: The Video Game is one of the greatest hits of the last... well, we don't remember quite how long. Our "computers" these days can't run much more than that, and it has a tendency to get repetitive...*

I connected to the game using netcat comamnd 'nc IP PORT'. I was met with a CLI-based game where the user had to respond with specific input to each command sent by the server. 
After going for 10 rounds, I realized that it was probably a very long game and that I had to create an automatic reply script. 

I used the library called pwn to help automaticly reply with commands based off the request sent by the server:

```
from pwn import *

r = remote('83.136.254.113', 55291)
r.recvuntil(b'(y/n) ')
r.sendline(b'y')
r.recvuntil(b'\n')

tries = 0

while True:
    try:
        got = r.recvline().decode()
        payload = got.replace(", ", "-").replace("GORGE", "STOP").replace("PHREAK", "DROP").replace("FIRE", "ROLL").strip()

        r.sendlineafter(b'What do you do?', payload.encode())
        tries = tries + 1
        log.info(f'{tries}: {payload}')
    except EOFError:
        log.success(got.strip())
        r.close()
        break
```
I ran the script against the IP and PORT given in the exercise and after 500 rounds the final message was: 
![image](https://github.com/user-attachments/assets/4213a98f-69e8-4d0e-9ee3-eeff567bf365)

Revealing the flag ***HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}***



# REVERSING

## LootStash

*A giant stash of powerful weapons and gear have been dropped into the arena - but there's one item you have in mind. Can you filter through the stack to get to the one thing you really need?*

I receive a file named *stash* and open it with notepad++.
With ctrl+f I am able to find the flag simply by searching for "HTB{" which is the start of the flag pattern.

***HTB{n33dl3_1n_a_l00t_stack}***

# CRYPTO

## Dynastic

Given
```
from secret import FLAG
from random import randint

def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def encrypt(m):
    c = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha():
            ech = ch
        else:
            chi = to_identity_map(ch)
            ech = from_identity_map(chi + i)
        c += ech
    return c

with open('output.txt', 'w') as f:
    f.write('Make sure you wrap the decrypted text with the HTB flag format :-]\n')
    f.write(encrypt(FLAG))"
```

### Code Overview:

1. **`to_identity_map` and `from_identity_map` Functions**:
    
    * `to_identity_map(a)` converts an uppercase letter (`A-Z`) to a number by subtracting 0x41 (which is the ASCII value of 'A').  
        * For example, `to_identity_map('A')` will return `0` and `to_identity_map('B')` will return `1`.
    * `from_identity_map(a)` converts a number back to a letter by using modulo 26 (to ensure it wraps around if needed) and adding 0x41 to map it back to an uppercase letter.  
        * For example, `from_identity_map(0)` will return `'A'` and `from_identity_map(1)` will return `'B'`.

2. **`encrypt(m)` Function**:
    
    This function encrypts the message `m`.  
    For each character in the message:
    
    * If the character is not alphabetic, it leaves it unchanged.
    * If it is alphabetic, it:
        1. Converts it to a number using `to_identity_map`.
        2. Adds the index `i` (the position of the character in the string).
        3. Converts it back to a letter using `from_identity_map`.

    This creates a Caesar-like cipher where each letter is shifted by its position in the string.


### Decryption Steps:

1. **Reversing the Encryption**:
    * For each character in the encrypted string:
        1. Convert it back to a number using `to_identity_map`.
        2. Subtract the index `i`.
        3. Convert it back to a letter using `from_identity_map`.

```python
def decrypt(c):
    m = ''
    # Iterate over each character in the encrypted string
    for i in range(len(c)):
        ch = c[i]
        
        # If the character is not alphabetic, leave it unchanged
        if not ch.isalpha():
            ech = ch
        else:
            # Convert the character back to its identity map (A -> 0, B -> 1, etc.)
            chi = to_identity_map(ch)
            
            # Subtract the current index 'i' from the identity map value
            # This reverses the encryption's shifting effect
            ech = from_identity_map(chi - i)
        
        # Append the decrypted character to the result string
        m += ech
    
    # Return the fully decrypted message
    return m

# Example usage
cipher_text = "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"
print(decrypt(cipher_text))  # Print out the decrypted text
```
Using the same identity mapping as the script given, I can easily revert back the ciphertext following a reverse order of action.

Flag was ***HTB{DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!_IT_IS_SIMILAR_TO_CAESAR_CIPHER}***


