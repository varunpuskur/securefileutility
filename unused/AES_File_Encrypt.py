'''

ENCRYPTING TEXT USING AES ALGORITHM
from Crypto.Cipher import AES

def pad(entry):
    # Calculate the necessary padding length
    padding_length = AES.block_size - len(entry) % AES.block_size
    # Create the padding
    padding = b"\0" * padding_length
    # Return the entry concatenated with the padding
    return entry + padding

plain_text = "This is a plain text"
# Encode plain_text to bytes before padding
plain_text = plain_text.encode('utf-8')
plain_text = pad(plain_text)

key = '12345'
# Ensure key is bytes before padding
key = key.encode('utf-8')
key = pad(key)

cipher = AES.new(key, AES.MODE_ECB)
cipher_text = cipher.encrypt(plain_text)
print(cipher_text)

cipher2 = AES.new(key, AES.MODE_ECB)
data = cipher2.decrypt(cipher_text)

data = data.decode('utf-8')
unpad = data.find("\0")
data = data[:unpad]

print(f" decode text = {data}") !!!TALK ABOUT WHY CFB AND NOT ECB!!!
'''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode

# Get the password from the user
user_file = input('Please insert the file name: ')
key = input('Please insert your password: ')
key = key.encode('UTF-8')
key = pad(key, AES.block_size)

def encrypt(file_name, key):
    with open(file_name, 'rb') as entry:
        data = entry.read()
        cipher = AES.new(key, AES.MODE_CFB)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        
        # Encode the IV and ciphertext in base64
        iv = b64encode(cipher.iv).decode('UTF-8')
        ciphertext = b64encode(ciphertext).decode('UTF-8')
        
        to_write = iv + ciphertext
    
    with open(file_name + '.enc', 'w') as data:
        data.write(to_write)
    data.close()

encrypt(user_file, key)