from PIL import Image
import io
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import streamlit as st

# Convert text to binary
def text_to_binary(text):  
    return ''.join(format(ord(char), '08b') for char in text)


# Encode message into image
def encode_image(image, message, password):

    message = encrypt_message(message, password)
    binary_message = text_to_binary(message) + '1111111111111110'  # 16-bit delimiter
    img = image.convert("RGB")  # Ensure image is in RGB mode
    
    pixels = img.load()
    width, height = img.size
    binary_index = 0

    for y in range(height):  
        for x in range(width):
            if binary_index < len(binary_message):  

                r, g, b = pixels[x, y]

                # Modify the red channel LSB
                r = (r & ~1) | int(binary_message[binary_index])
                binary_index += 1

                # Modify the green channel LSB
                if binary_index < len(binary_message):
                    g = (g & ~1) | int(binary_message[binary_index])
                    binary_index += 1

                # Modify the blue channel LSB
                if binary_index < len(binary_message):
                    b = (b & ~1) | int(binary_message[binary_index])
                    binary_index += 1

                pixels[x, y] = (r, g, b)

    # Save modified image to BytesIO
    output_image = io.BytesIO()
    img.save(output_image, format="PNG")
    output_image.seek(0)
    return output_image


# Decode message from image
def decode_image(image, password):

    img = image.convert("RGB")
    pixels = img.load()
    width, height = img.size

    binary_message = []

    for y in range(height):  
        for x in range(width):

            r, g, b = pixels[x, y]
            binary_message.append(str(r & 1))
            binary_message.append(str(g & 1))
            binary_message.append(str(b & 1))

    binary_message = ''.join(binary_message)


    # Extract message until delimiter
    message = ""
    for i in range(0, len(binary_message), 8):  
        byte = binary_message[i:i+8]
        if len(byte) < 8:
            continue
        if binary_message[i:i+16] == '1111111111111110':  
            break
        message += chr(int(byte, 2))

    return decrypt_message(message, password)


# Key Derivation from Password
def derive_key(password: str, salt: bytes):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())  


# AES encryption 
def encrypt_message(message, password):

    salt = os.urandom(16)  # Salt call that makes random non-repeated salt
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad message to make its length a multiple of 16 bytes
    pad_length = 16 - (len(message) % 16)
    padded_message = message + chr(pad_length) * pad_length

    encrypted_message = encryptor.update(padded_message.encode()) + encryptor.finalize()

    return base64.b64encode(salt + iv + encrypted_message).decode()


# Extract salt, IV and decrypt message
def decrypt_message(encrypted_message, password):

    decoded_data = base64.b64decode(encrypted_message)
    salt, iv, encrypted_data = decoded_data[:16], decoded_data[16:32], decoded_data[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(encrypted_data) + decryptor.finalize()

    # Fix: Remove padding correctly
    pad_length = decrypted_message[-1]  # Fix: changed ord(decrypted_message[-1:])
    return decrypted_message[:-pad_length].decode()


#Streamlit Interface:

st.title("Steganography with Encryption")

# Option to choose between encoding and decoding
option = st.selectbox("Select Action", ("Encode Message", "Decode Message"))

if option == "Encode Message":
    # Input message and image for encoding
    uploaded_image = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
    message = st.text_area("Enter Message to Hide")
    password = st.text_input("Enter a Password for Encryption", type="password")

    if uploaded_image and message and password:
        # Open image
        image = Image.open(uploaded_image)

        # Encode image with the message
        encoded_image = encode_image(image, message, password)

        # Provide the encoded image to download
        st.image(encoded_image, caption="Encoded Image", use_column_width=True)
        
        # Allow download of encoded image
        encoded_image_base64 = base64.b64encode(encoded_image.getvalue()).decode()
        download_link = f'<a href="data:image/png;base64,{encoded_image_base64}" download="encoded_image.png">Download Encoded Image</a>'
        st.markdown(download_link, unsafe_allow_html=True)

elif option == "Decode Message":
    # Input for decoding
    uploaded_image = st.file_uploader("Upload Encoded Image", type=["png", "jpg", "jpeg"])
    password = st.text_input("Enter Password for Decryption", type="password")

    if uploaded_image and password:
        # Open image
        image = Image.open(uploaded_image)

        # Decode message from the image
        decoded_message = decode_image(image, password)

        # Show decoded message
        if decoded_message:
            st.write("Decoded Message: ", decoded_message)
        else:
            st.write("Incorrect password.")

