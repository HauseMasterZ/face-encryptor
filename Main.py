import tkinter as tk
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature
import secrets
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cv2
from tkinter import messagebox
from PIL import Image, ImageTk
import face_recognition
import os
import threading


def generate_key_file():    
    key = secrets.token_bytes(32)  # Generate a 256-bit (32-byte) random key
    return key

# Generates Padding For AES CBC
def pad_file(plaintext):
    block_size = algorithms.AES.block_size // 8
    padding_size = block_size - (len(plaintext) % block_size)
    padding = bytes([padding_size] * padding_size)
    return plaintext + padding

# Removes Padding For AES CBC
def unpad_file(padded_text):
    padding_size = padded_text[-1]
    return padded_text[:-padding_size]
    

# Encrypts a filename using AES CBC
def encrypt_file(plaintext, key):
    backend = default_backend()
    # Generate a random IV
    iv = secrets.token_bytes(algorithms.AES.block_size // 8)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padded_text = pad_file(plaintext.encode())
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    return iv + key + ciphertext

# Decrypts a filename using AES CBC
def decrypt_file(ciphertext):
    backend = default_backend()
    iv = ciphertext[:algorithms.AES.block_size // 8]
    key = ciphertext[algorithms.AES.block_size //
                     8:algorithms.AES.block_size // 8 + 32]
    ciphertext = ciphertext[algorithms.AES.block_size // 8 + 32:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_text = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad_file(padded_text).decode()
    return plaintext

secretsGenerator = secrets.SystemRandom()

# Generate a 32-byte key using PBKDF2 key derivation function
def generate_key(password, name, salt=None):
    if salt is None:
        salt = secrets.token_bytes(32)
    # Change this to your own salt value or use this 
    hmac_salt = b"!\xb3\xc1\xa6U9{\x01'\xf4uq\x8a4c\xeb\xb6a\x18\xd4Uo\xbf\xc5\tu\x80\xf2\xee!h\xf6"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Encryption Key Length
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    encryption_key = base64.urlsafe_b64encode(
        kdf.derive(password.encode() + name.encode()))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # HMAC key length
        salt=hmac_salt,
        iterations=100000,
        backend=default_backend(),
    )
    hmac_key = base64.urlsafe_b64encode(
        kdf.derive(password.encode() + name.encode()))
    return encryption_key, hmac_key, salt


trained_flag = False

# Train the face recognition model and encrypt the message
def encrypt_message():
    if not trained_flag:
        messagebox.showwarning('Face Not Recognized',
                               'Please Verify your face first for entity authentication')
        return
    password = password_entry.get()
    if password == '':
        messagebox.showwarning('Enter Passkey',
                               'It is very insecure to encrypt your message only using the salt and face. Please enter a strong passkey.')
        return
    message = message_text.get("1.0", "end-1c").strip()
    encryption_key, hmac_key, salt = generate_key(password + secretsGenerator.choice(string.ascii_letters), decrypt_file(bytes.fromhex(all_faces[-1])))
    cipher_suite = Fernet(encryption_key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    salted_encrypted_message = salt + encrypted_message
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(salted_encrypted_message)
    hmac_value = h.finalize()
    encrypted_window = tk.Toplevel(root)
    encrypted_window.minsize(200, 50)
    encrypted_window.geometry('400x200')
    encrypted_window.configure(background='red')
    clipboard_text = tk.Label(encrypted_window, text='Copied to clipboard',
                              foreground='#3d0d0d', font=('Roboto', 10), background='red')
    clipboard_text.place(anchor=tk.E, relx=0.99, rely=0.1)
    output_label = tk.Label(encrypted_window, text="ENCRYPTED CIPHER: ",
                            background='red', foreground='White', font=("Aerial", 15))
    output_label.place(anchor=tk.W, relx=0.1, rely=0.1)
    output_text = tk.Text(encrypted_window, height=5,
                          width=30, relief=tk.GROOVE, bd=0, font=("Roboto", 10))
    output_text.place(anchor=tk.CENTER, relx=0.5, rely=0.53,
                      relwidth=0.85, relheight=0.6)
    cipher = (salt.hex() + encrypted_message.decode() + hmac_value.hex())
    output_text.insert("1.0", cipher)
    root.clipboard_clear()
    root.clipboard_append(cipher)
    output_text.configure(state="disabled")
    encrypted_window.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'FaceEncryptor.ico'))


# Contains the list of all the matched faces
all_faces = []

# Train the face recognition model and decrypt the message
def decrypt_message():
    global decrypting

    if not trained_flag:
        messagebox.showwarning('Face Not Recognized',
                               'Please Verify your face first for entity authentication')
        encrypt_button.configure(text='ENCRYPT')
        return
    password = password_entry.get()
    message = message_text.get("1.0", "end-1c")
    hmac_length = 64
    salted_encrypted_message = message[:-hmac_length]
    salt = salted_encrypted_message[:64]
    received_hmac = message[-hmac_length:]
    try:
        salt = bytes.fromhex(salt)
        encrypted_message = salted_encrypted_message[64:].encode()
    except ValueError:
        messagebox.showerror('HMAC verification failed.',
                        'The message may have been tampered with during transit.')
        encrypt_button.configure(text='ENCRYPT')
        return
    tampered_message = False
    incorrect_password = True
    for i in string.ascii_letters:
        if not incorrect_password:
            break
        for curr_face in all_faces:
            ciphertext_bytes = bytes.fromhex(curr_face)
            encryption_key, hmac_key, salt = generate_key(
                password+i, decrypt_file(ciphertext_bytes), salt)
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(salt + encrypted_message)
            try:
                h.verify(bytes.fromhex(received_hmac))
            except InvalidSignature:
                tampered_message = True
            except:
                incorrect_password = True
                break
            else:
                tampered_message = False
                incorrect_password = False
                break
    if incorrect_password:
        decrypt_button.configure(text='DECRYPT')
        messagebox.showerror('Wrong Passkey',
                'Please Try Again.')
    elif tampered_message:
        decrypt_button.configure(text='DECRYPT')

        messagebox.showerror('HMAC verification failed.',
                'The message may have been tampered with during transit.')
    else:
        decrypted_window = tk.Toplevel(root)
        decrypted_window.minsize(200, 50)
        decrypted_window.geometry('400x200')
        decrypted_window.configure(background='red')
        clipboard_text = tk.Label(decrypted_window, text='Copied to clipboard',
                                  foreground='#3d0d0d', font=('Roboto', 10), background='red')
        clipboard_text.place(anchor=tk.E, relx=0.99, rely=0.1)
        output_label = tk.Label(decrypted_window, text="DECRYPTED MESSAGE: ",
                                background='red', foreground='White', font=("Aerial", 15))
        output_label.place(anchor=tk.W, relx=0.1, rely=0.1)
        output_text = tk.Text(decrypted_window, height=5,
                              width=30, relief=tk.GROOVE, bd=0, font=("Roboto", 10))
        output_text.place(anchor=tk.CENTER, relx=0.5, rely=0.53,
                          relwidth=0.85, relheight=0.6)
        cipher_suite = Fernet(encryption_key)
        decrypted_message = cipher_suite.decrypt(encrypted_message)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decrypted_message.decode())
        root.clipboard_clear()
        root.clipboard_append(decrypted_message.decode())
        output_text.configure(state="disabled")
        def loop():
            output_label.after(1000, loop)

        def close():
            global decrypting
            output_label.destroy()
            output_text.delete("1.0", tk.END)
            decrypted_window.destroy()
            decrypt_button.configure(text='DECRYPT')
            decrypting = False
            encrypt_button.configure(text='ENCRYPT')
        decrypted_window.protocol("WM_DELETE_WINDOW", close)
        decrypted_window.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'FaceEncryptor.ico'))


    decrypting = False
    
    

# Reset the fields
def resetField():
    password_entry.delete(0, tk.END)
    message_text.delete("1.0", "end-1c")

# Check if the face is already in the database
def compareFaces(photo, database_folder):
    input_image = photo
    input_encoding = face_recognition.face_encodings(
        input_image)  # Assume only one face in the input photo
    if len(input_encoding) == 0:
        return all_faces
    input_encoding = input_encoding[0]
    for folder in os.listdir(database_folder):
        for filename in os.listdir(os.path.join(database_folder, folder)):
            if not filename.lower().endswith(('.jpg', '.jpeg', '.png')):
                continue
            database_image = face_recognition.load_image_file(
                os.path.join(database_folder, folder, filename))
            database_encoding = face_recognition.face_encodings(
                database_image)[0]  # Assume only one face in each database photo

            results = face_recognition.compare_faces(
                [input_encoding], database_encoding)
            if results[0]:
                all_faces.append(folder)
                break
    else:
        return all_faces

# Detect the face in the video feed
def detectFace(event = None):
    all_faces.clear()
    video_capture = cv2.VideoCapture(0)
    face_recognition_window = tk.Toplevel(root)
    face_recognition_window.grab_set()
    face_recognition_window.geometry(
        f"{int(root.winfo_screenwidth()/2)}x{int(root.winfo_screenheight()/1.5)}")
    face_recognition_window.title("Train Model")
    face_cascade = cv2.CascadeClassifier(
        cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    name_entry_field = tk.Entry(
        face_recognition_window, relief=tk.GROOVE, bd=1, font=("Roboto", 10), show='*')

    video_label = tk.Label(face_recognition_window)
    video_label.place(anchor=tk.CENTER, relx=0.5,
                      rely=0.4, relheight=0.75, relwidth=1)
    found_label = tk.Label(face_recognition_window)
    # Update the video feed
    def update_new_frame():

        ret, frame = video_capture.read()  # Read frame from the camera
        if ret:
            small_frame = cv2.resize(frame, (0, 0), fx=0.5, fy=0.5)
            gray = cv2.cvtColor(small_frame, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
            for (x, y, w, h) in faces:
                # Scale the face coordinates back to the original frame size
                x *= 2
                y *= 2
                w *= 2
                h *= 2
                if not all_faces:
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 0, 255), 2)
                else:
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
            # Display the frame in the new window
            image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image = Image.fromarray(image)
            photo = ImageTk.PhotoImage(image)
            video_label.config(image=photo)
            video_label.image = photo

        video_label.after(30, update_new_frame)  # Call after 30ms
    
    # Search for the face in the database
    def trainModel():
        global user_photo, trained_flag
        # compare_face_thread.start()
        ret, frame = video_capture.read()  # Read frame from the camera
        compareFaces(frame.copy(), os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'database'))
        if all_faces:
            found_label.configure(text=f'MATCH FOUND!  Closing...', foreground='Green')
            scan_button.configure(background='Green')
            trained_flag = True
            face_recognition_window.after(2000, lambda : on_face_close())
        else:
            found_label.place(anchor=tk.E, relx=0.5, rely=0.8)
            found_label.configure(
                text='MATCH NOT FOUND, ENTER RECIPIENT NAME: ', foreground='Red')
            scan_button.configure(background='Red')
            name_entry_field.place(anchor=tk.W, relx=0.51, rely=0.8)
            name_entry_field.focus_set()
            user_photo = frame.copy()
        scan_button.configure(text='Train Model')
    # Thread to search for the face in the database
    def trainModelThreadAction():
        name_entry_field.place_forget()
        found_label.place(anchor=tk.CENTER, relx=0.5, rely=0.8)

        scan_button.configure(text='Training...', background='Red')
        found_label.configure(text='Please Wait...',)
        model_thread = threading.Thread(target=trainModel)
        model_thread.start()

    # On closing the window
    def on_face_close(event = None):
        global user_photo, trained_flag
        if not all_faces and name_entry_field.get().strip() != '':
            user_name_key = generate_key_file()
            encrypted_user_name = encrypt_file(
                name_entry_field.get(), user_name_key)
            name_entry_field.delete(0, tk.END)
            ciphertext_encoded = encrypted_user_name.hex()
            all_faces.append(ciphertext_encoded)
            new_folder = os.path.join(os.path.dirname(
                os.path.abspath(__file__)), 'database', ciphertext_encoded)
            curr_number = 1
            try:
                os.makedirs(new_folder)
            except OSError:
                try:
                    curr_number = int(os.path.splitext(
                        os.listdir(new_folder)[-1])[0]) + 1
                except:
                    curr_number = 1
            image_path = os.path.join(new_folder, f"{curr_number}.jpg")
            cv2.imwrite(image_path, user_photo)
            trained_flag = True
        if trained_flag:
            on_label.configure(text='Yes', foreground='Green')
        else:
            on_label.configure(text='No', foreground='Red')
        video_capture.release()
        cv2.destroyAllWindows()
        face_recognition_window.destroy()

    scan_button = tk.Button(face_recognition_window,
                            text='Train Model', command=trainModelThreadAction, padx=6, pady=6, relief=tk.RAISED, bd=1, activeforeground='gray')
    scan_button.configure(background='red')
    scan_button.place(anchor=tk.CENTER, relx=0.5, rely=0.9,
                      relwidth=0.12, relheight=0.1)
    name_entry_field.bind("<Return>", on_face_close)
    face_recognition_window.protocol("WM_DELETE_WINDOW", on_face_close)
    face_recognition_window.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'FaceRecognition.ico'))
    
    update_new_frame()



# Create the main root
root = tk.Tk()
try:
    root.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'FaceEncryptor.ico'))
except:
    pass
root.configure(background='#f0f0f0')
root.geometry(f"{root.winfo_screenwidth()//4}x{root.winfo_screenheight()//2}")

root.title("Face Encryptor ~ HauseMaster")

# Create the message label and text box
trained_label = tk.Label(
    root, text="Face Trained: ", font=("Roboto", 10))
trained_label.place(anchor=tk.E, relx=0.57, rely=0.96)
on_label = tk.Label(root, text='No')
on_label.configure(foreground='Red')
on_label.place(anchor=tk.W, relx=0.57, rely=0.96)
message_text = tk.Text(root, relief=tk.GROOVE, bd=0, font=("Roboto", 10))
message_text.configure(height=5)
message_text.place(anchor=tk.CENTER, relx=0.5, rely=0.22, relwidth=0.95)

message_label = tk.Label(
    root, text="Enter Text for Encryption/Decryption:", font=("Roboto", 10))
message_label.place(anchor=tk.W, relx=0.02, rely=0.07)


# Create the password label and text box
password_entry = tk.Entry(
    root, show="*", relief=tk.GROOVE, bd=0, font=("Roboto", 12))
password_entry.place(anchor=tk.CENTER, relx=0.5, rely=0.46, relwidth=0.95)
password_label = tk.Label(
    root, text="Enter Passkey for Encryption/Decryption:", font=("Roboto", 10))
password_label.place(anchor=tk.W, relx=0.02, rely=0.4)

# Create the encrypt and decrypt buttons
encrypt_button = tk.Button(root, text="ENCRYPT", command=encrypt_message)
encrypt_button.configure(background='Red', foreground='White',
                         activeforeground='Gray', activebackground='#3d0d0d', relief=tk.SUNKEN, bd=0)
encrypt_button.place(anchor=tk.E, relx=0.45, rely=0.72,
                     relwidth=0.4, relheight=0.1)
decrypting = False
def decryptThreadAction():
    global decrypting
    if decrypting:
        messagebox.showwarning('Decrypting still processing',
                        'Please Wait.')
        return
    decrypt_button.configure(text='DECRYPTING...')
    decrypting = True
    decrypt_thread = threading.Thread(target=decrypt_message)
    decrypt_thread.start()


    

decrypt_button = tk.Button(root, text="DECRYPT", command=decryptThreadAction)
decrypt_button.configure(background='#1bd11b', foreground='White',
                         activeforeground='Gray', activebackground='#0d3d0d', relief=tk.SUNKEN, bd=0)
decrypt_button.place(anchor=tk.W, relx=0.55, rely=0.72,
                     relwidth=0.4, relheight=0.1)

# Create the reset button
reset_button = tk.Button(root, text="RESET", command=resetField)
reset_button.configure(background='#0f88f8', foreground='White',
                       activeforeground='Gray', activebackground='#151b54', relief=tk.SUNKEN, bd=0)
reset_button.place(anchor=tk.CENTER, relx=0.5,
                   rely=0.87, relwidth=0.91, relheight=0.1)

# Create the train button
train_button = tk.Button(root, text="TRAIN MODEL", command=detectFace)
train_button.configure(background='orange', foreground='White',
                       activeforeground='Gray', activebackground='#a16d13', relief=tk.SUNKEN, bd=0)
train_button.place(anchor=tk.CENTER, relx=0.5,
                   rely=0.58, relwidth=0.91, relheight=0.1)


# Start the main loop
root.mainloop()
