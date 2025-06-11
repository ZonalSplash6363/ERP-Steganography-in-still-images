from PIL import Image
import streamlit as st
import io
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes




# ===TO RUN CORRECTLY, PRESS RUN THEN TYPE: "streamlit run <name_of_file.py>"====



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

    # Save modified image to bytesIO
    output_image = io.BytesIO()
    img.save(output_image, format="PNG")
    output_image.seek(0)
    return output_image


# Decode message from image
def decode_image(image):
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

    return message


# Key Derivation from Password
def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length = 32,
        salt=salt(),
        iterations = 10000,
        backend=default_backend()
    )
    return kdf.derive(password.encode) # Returns a 32-byte encryption key


# AES encryption 
def encrypt_message(message, password):
    salt = os.urandom(16) # random for each encryption
    key = derive_key(password , salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad message to make its length a multiple of 16 bytes
    pad_length = 16 - (len(message) % 16)
    padded_message = message + chr(pad_length) * pad_length

    encrypted_message = encryptor.update(padded_message.encode()) + encryptor.finalize()

    return base64.b64encode(salt + iv + encrypted_message).decode()



# Extracting the salt and IV and decrypts the message
def decrypt_message(encrypted_message, password):
    decoded_data = base64.b64decode(encrypted_message)
    salt, iv, encrypted_data = decoded_data[:16], decoded_data[16:32], decoded_data[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    pad_length = ord(decrypted_message[-1:])
    return decrypted_message[:-pad_length].decode()



# Streamlit user interface
st.title("Steganography: Hide and Retrieve Messages in Images")
st.write(
    "Upload any still image. The app will calculate exactly how many characters/"
    "bytes can be hidden and will warn you if your input is too large."
)

tab1, tab2 = st.tabs(["Encode Message", "Decode Message"])

# Encode Tab
with tab1:
    st.header("Hide a Message")
    uploaded_image = st.file_uploader("Upload an image file", type=["jpg", "jpeg", "png"])
    message = st.text_area("Enter the message to hide")
    password = st.text_input("Enter a password for encryption", type="password")
    # NEW: optional text‑file uploader for message input
    text_file = st.file_uploader("…or upload a .txt file to hide", type=["txt"])
    if text_file is not None:
        try:
            file_bytes = text_file.read()
            message = file_bytes.decode("utf-8", errors="ignore")
        except Exception as e:
            st.error(f"Error reading text file: {e}")
    
    if st.button("Encode Message"):
        if uploaded_image and message and password:
            # Open the image first, then calculate its individual capacity
            try:
                image = Image.open(uploaded_image)
            except Exception as e:
                st.error(f"Cannot open image: {e}")
                st.stop()

            capacity_bits = image.size[0] * image.size[1] * 3      # 3 LSBs per pixel
            capacity_chars = (capacity_bits // 8) - 2              # leave space for delimiter
            capacity_bytes = capacity_chars  # 1 char ≈ 1 byte for utf‑8 text
            if len(message) > capacity_chars:
                st.error(
                    f"Message is too large for this image.\n"
                    f"Max characters allowed: {capacity_chars}."
                )
                st.stop()
            if text_file is not None and len(file_bytes) > capacity_bytes:
                st.error(
                    f"Text file exceeds per‑image limit of {capacity_bytes} bytes."
                )
                st.stop()

            try:
                output_image = encode_image(image, message, password)
                
                # Provide a download link
                st.success("Message encoded successfully! Download the encoded image below:")
                st.download_button("Download Encoded Image", output_image, file_name="encoded_image.png", mime="image/png")
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Please upload an image, enter a message, and provide a password.")

# Decode Tab
with tab2:
    st.header("Retrieve a Hidden Message")
    uploaded_image_decode = st.file_uploader("Upload an image file to decode", type=["png"])
    
    if st.button("Decode Message"):
        if uploaded_image_decode:
            try:
                image = Image.open(uploaded_image_decode)
                hidden_message = decode_image(image)
                if hidden_message:
                    st.success(f"Hidden message: {hidden_message}")
                else:
                    st.warning("No hidden message found in the image.")

            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Please upload a .png image to decode.")


