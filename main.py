import os
import pgpy
from PyPDF2 import PdfReader

# Hardcoded key file paths
PUBLIC_KEY_FILE = os.path.join("config", "public_key.asc")
PRIVATE_KEY_FILE = os.path.join("config", "private_key.asc")
PASSPHRASE = "12345"

def load_key_from_file(file_path):
    with open(file_path, 'r') as file:
        key_str = file.read()
    return pgpy.PGPKey.from_blob(key_str)[0]

def encrypt_message(public_key_file, message):
    public_key = load_key_from_file(public_key_file)
    message_obj = pgpy.PGPMessage.new(message)
    encrypted_message = public_key.encrypt(message_obj)
    return encrypted_message

def decrypt_message(private_key_file, passphrase, encrypted_message_str):
    try:
        private_key = load_key_from_file(private_key_file)
        with private_key.unlock(passphrase):
            encrypted_message = pgpy.PGPMessage.from_blob(encrypted_message_str)
            decrypted_message = private_key.decrypt(encrypted_message)
            return decrypted_message.message
    except pgpy.errors.PGPError as e:
        print("Decryption failed:", e)
        return None

def read_text_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def read_pdf_file(file_path):
    reader = PdfReader(file_path)
    text = ''
    for page in reader.pages:
        text += page.extract_text()
    return text

def write_text_file(file_path, content):
    with open(file_path, 'w') as file:
        file.write(content)

def main():
    try:
        # Define the source and destination folders
        source_folder = "source"
        destination_folder = "destination"

        # Create the destination folder if it doesn't exist
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)

        # Process each file in the source folder
        for file_name in os.listdir(source_folder):
            file_path = os.path.join(source_folder, file_name)
            if os.path.isfile(file_path):
                if file_name.endswith('.txt'):
                    # Read text file
                    message = read_text_file(file_path)
                elif file_name.endswith('.pdf'):
                    # Read PDF file
                    message = read_pdf_file(file_path)
                else:
                    print(f"Unsupported file type: {file_name}")
                    continue

                # Encrypt the message using the public key
                encrypted_message = encrypt_message(PUBLIC_KEY_FILE, message)
                print(f"\nMessage from {file_name} successfully encrypted.")

                # Save the encrypted message to a file named after the input file
                encrypted_message_file_name = f"{file_name}_encrypted.asc"
                encrypted_message_file_path = os.path.join(destination_folder, encrypted_message_file_name)
                write_text_file(encrypted_message_file_path, str(encrypted_message))
                print(f"Encrypted message saved to: {encrypted_message_file_path}")

                # Optionally, read the encrypted message from the file to verify decryption
                with open(encrypted_message_file_path, 'r') as file:
                    encrypted_message_str = file.read()

                # Decrypt the message using the private key and passphrase
                decrypted_message = decrypt_message(PRIVATE_KEY_FILE, PASSPHRASE, encrypted_message_str)
                if decrypted_message:
                    print(f"\nMessage from {file_name} successfully decrypted.")
                    print(f"Decrypted message:\n{decrypted_message[:100]}...")  # Print the first 100 characters of the decrypted message
                else:
                    print(f"\nDecryption of {file_name} failed.")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()

