from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from base64 import b64decode
import getpass
import os

# Get the decryption key from the user
user_file = input('Please insert the file name: ')
key = getpass.getpass('Please enter your password: ')
key = key.encode('UTF-8')
key = pad(key, AES.block_size)

# Attempt to open and decrypt the file
try:
    with open(user_file, 'rb') as entry:
        data = entry.read()
        length = len(data)
        
        # Extract the IV and ciphertext
        iv = data[:24]
        iv = b64decode(iv)
        ciphertext = data[24:length]
        ciphertext = b64decode(ciphertext)
        
        # Initialize the cipher and decrypt
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted, AES.block_size)
        
        # Generate the output file name by removing the .enc extension and adding _decrypted before the file extension
        if user_file.endswith('.enc'):
            # Remove the .enc extension
            base_name = user_file[:-4]  # Remove the last 4 characters, which is '.enc'
        else:
            base_name = user_file
        
        # Split the base name into name and extension
        name, ext = os.path.splitext(base_name)
        
        # Construct the new filename with '_decrypted' before the extension
        output_file = f"{name}_decrypted{ext}"
        
        # Write the decrypted data to the new file
        with open(output_file, 'wb') as data:
            data.write(decrypted)
except (ValueError, KeyError):
    print('Wrong password')
