import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time


def pad_data(data):
    block_size = 16
    return pad(data, block_size)


def unpad_data(data):
    return unpad(data, AES.block_size)


class ECBMode:
    def __init__(self, key):
        self.key = key

    def aes_encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def aes_decrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(data)

    def encrypt(self, data):
        padded_data = pad_data(data)
        return self.aes_encrypt(padded_data)

    def decrypt(self, data):
        decrypted_data = self.aes_decrypt(data)
        return unpad_data(decrypted_data)


class CBCMode:
    def __init__(self, key):
        self.key = key

    def aes_encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def aes_decrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(data)

    def encrypt(self, data, iv):
        cipher = AES.new(self.key)
        iv = bytearray(iv)
        encrypted_data = bytearray()

        for i in range(0, len(data), AES.block_size):
            block = data[i : i + AES.block_size]
            block = pad_data(block)
            block = bytearray(a ^ b for a, b in zip(block, iv))
            encrypted_block = cipher.encrypt(bytes(block))
            iv = bytearray(encrypted_block)
            encrypted_data.extend(encrypted_block)

        return bytes(encrypted_data)

    def decrypt(self, data, iv):
        cipher = AES.new(self.key, AES.MODE_ECB)
        iv = bytearray(iv)
        decrypted_data = bytearray()

        for i in range(0, len(data), AES.block_size):
            block = data[i : i + AES.block_size]
            decrypted_block = cipher.decrypt(bytes(block))
            decrypted_block = bytearray(a ^ b for a, b in zip(decrypted_block, iv))
            iv = bytearray(block)
            decrypted_data.extend(decrypted_block)

        return unpad_data(bytes(decrypted_data))


class CTRMode:
    def __init__(self, key):
        self.key = key

    def aes_encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def encrypt(self, data, nonce):
        cipher = AES.new(self.key, AES.MODE_ECB)
        counter = nonce
        encrypted_data = bytearray()

        for i in range(0, len(data), AES.block_size):
            block = data[i : i + AES.block_size]
            encrypted_block = cipher.encrypt(counter)
            encrypted_block = bytearray(a ^ b for a, b in zip(block, encrypted_block))
            encrypted_data.extend(encrypted_block)
            counter = increment_counter(counter)

        return bytes(encrypted_data)


class CCMMode:
    def __init__(self, key):
        self.key = key

    def aes_encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def encrypt(self, data, nonce):
        iv = nonce + b"\x00\x00\x00\x00\x00"  # Concatenate nonce and flags
        mode = CTRMode(self.key)
        encrypted_data = mode.encrypt(data, iv)

        mac_data = iv + encrypted_data
        mac = self.generate_mac(mac_data)
        return encrypted_data + mac

    def generate_mac(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        mac = b"\x00" * AES.block_size  # Initialize MAC with zeroes

        for i in range(0, len(data), AES.block_size):
            block = data[i : i + AES.block_size]
            mac = bytearray(a ^ b for a, b in zip(block, mac))
            mac = cipher.encrypt(bytes(mac))

        return mac


class AESModes:
    def __init__(self):
        self.key = b""
        self.mode = None

    def encrypt(self, data, iv=None, nonce=None):
        if self.mode == "ECB":
            mode = ECBMode(self.key)
            return mode.encrypt(data), None
        elif self.mode == "CBC":
            mode = CBCMode(self.key)
            iv = get_random_bytes(16) if iv is None else iv
            return mode.encrypt(data, iv), iv
        elif self.mode == "CTR":
            mode = CTRMode(self.key)
            nonce = get_random_bytes(8) if nonce is None else nonce
            return mode.encrypt(data, nonce), nonce
        elif self.mode == "CCM":
            mode = CCMMode(self.key)
            nonce = get_random_bytes(8) if nonce is None else nonce
            return mode.encrypt(data, nonce), nonce

    def decrypt(self, data, iv=None, nonce=None):
        if self.mode == "ECB":
            mode = ECBMode(self.key)
            return mode.decrypt(data)
        elif self.mode == "CBC":
            mode = CBCMode(self.key)
            return mode.decrypt(data, iv)
        elif self.mode == "CTR":
            mode = CTRMode(self.key)
            return mode.decrypt(data, nonce)
        elif self.mode == "CCM":
            mode = CCMMode(self.key)
            return mode.decrypt(data, nonce)


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Cipher")
        self.cipher = AESModes()

        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=0, column=0, padx=20, pady=20)

        self.text_label = tk.Label(
            self.input_frame, text="Input:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=0, column=0)
        self.loaded_file_label = tk.Label(
            self.input_frame, text="<No file loaded>", width=45
        )
        self.loaded_file_label.grid(row=0, column=1)

        self.text_label = tk.Label(
            self.input_frame, text="Key:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=1, column=0)
        self.key_label = tk.Label(self.input_frame, text="<No key loaded>", width=45)
        self.key_label.grid(row=1, column=1)

        self.output_label = tk.Label(
            self.input_frame, text="Output:", width=8, font=("Helvetica", 13, "bold")
        )
        self.output_label.grid(row=3, column=0)
        self.output_file_label = tk.Label(
            self.input_frame, text="<Encrypt/Decrypt a file..>", width=45
        )
        self.output_file_label.grid(row=3, column=1)

        self.mode_label = tk.Label(
            self.input_frame, text="Mode:", width=8, font=("Helvetica", 13, "bold")
        )
        self.mode_label.grid(row=4, column=0)
        self.mode = tk.StringVar()
        self.mode.set("ECB")
        self.mode_menu = tk.OptionMenu(
            self.input_frame,
            self.mode,
            "ECB",
            "CBC",
            "CTR",
            "CCM",
            command=self.set_mode,
        )
        self.mode_menu.config(width=8)
        self.mode_menu.grid(row=4, column=1, pady=3)

        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=4, column=0, padx=20, pady=20)

        self.load_file_button = tk.Button(
            self.button_frame,
            text="Load file..",
            command=self.load_file,
            width=8,
        )
        self.load_file_button.grid(row=0, column=0)

        self.generate_key_button = tk.Button(
            self.button_frame, text="Generate key", command=self.generate_key, width=8
        )
        self.generate_key_button.grid(row=1, column=0)

        self.upload_key_button = tk.Button(
            self.button_frame, text="Load key..", command=self.load_key, width=8
        )
        self.upload_key_button.grid(row=1, column=1)

        self.encrypt_button = tk.Button(
            self.button_frame, text="Encrypt", command=self.encrypt_file, width=8
        )
        self.encrypt_button.grid(row=3, column=0)

        self.decrypt_button = tk.Button(
            self.button_frame, text="Decrypt", command=self.decrypt_file, width=8
        )
        self.decrypt_button.grid(row=3, column=1)

        self.loaded_file_content = None
        self.encrypted_content = None
        self.decrypted_content = None
        self.encryption_mode = True  # True za šifriranje, False za dešifriranje

    def set_mode(self, mode):
        self.cipher.mode = mode
        print(f"Mode set to {mode}.")

    def generate_key(self):
        self.cipher.key = os.urandom(16)
        self.key_label.config(text="Key generated and loaded.")
        self.save_key()

    def save_key(self):
        if self.cipher.key:
            file_path = filedialog.asksaveasfilename(
                filetypes=[("Text Files", "*.txt")]
            )
            with open(file_path, "wb") as file:
                file.write(self.cipher.key)
        else:
            messagebox.showerror("Error", "No key generated to save!")

    def load_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "rb") as file:
                self.cipher.key = file.read()
                self.key_label.config(text="Key loaded.")
        else:
            messagebox.showerror("Error", "No key uploaded!")

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if file_path:
            self.loaded_file_label.config(text=f'"{file_path.split("/")[-1]}"')
            with open(file_path, "rb") as file:
                self.loaded_file_content = file.read()
                self.output_file_label.config(text="File loaded and ready.")
        else:
            self.loaded_file_label.config(text="<No file loaded>")
            self.output_file_label.config(text="<Encrypt/decrypt a file..>")

    def save_output(self):
        if self.encryption_mode and self.encrypted_content:
            content = self.encrypted_content
        elif not self.encryption_mode and self.decrypted_content:
            content = self.decrypted_content
        else:
            messagebox.showerror("Error", "No content to save!")
            return

        file_path = filedialog.asksaveasfilename(filetypes=[("All Files", "*.*")])
        with open(file_path, "wb") as file:
            file.write(content)

    def encrypt_file(self):
        if self.loaded_file_content:
            if self.cipher.key is None:
                messagebox.showerror("Error", "No key loaded!")
                return
            start = time.time()
            print(f"Starting encryption..")
            self.encrypted_content = self.cipher.encrypt(self.loaded_file_content)
            print(f"Encryption finished!")
            end = time.time()
            elapsed_time = end - start
            encryption_speed = len(self.loaded_file_content) / (
                elapsed_time * 1024 * 1024
            )
            print(f"Encryption speed: {round(encryption_speed, 2)} MB/s")
            print(f"Elapsed time: {round(elapsed_time, 2)}s")
            self.output_file_label.config(text="File encrypted!")
            self.encryption_mode = True
            self.save_output()
        else:
            messagebox.showerror("Error", "No file loaded!")

    def decrypt_file(self):
        if self.loaded_file_content:
            if self.cipher.key is None:
                messagebox.showerror("Error", "No key loaded!")
                return
            start = time.time()
            print(f"Starting decryption..")
            self.decrypted_content = self.cipher.decrypt(self.loaded_file_content)
            print(f"Decryption finished!")
            end = time.time()
            print(
                f"Decryption speed: {round((len(self.loaded_file_content) / (end - start)), 2)} B/s"
            )
            print(f"Elapsed time: {round((end - start), 2)}s")
            self.output_file_label.config(text="File decrypted!")
            self.encryption_mode = False
            self.save_output()
        else:
            messagebox.showerror("Error", "No file loaded!")


if __name__ == "__main__":
    root = tk.Tk()
    gui = GUI(root)
    root.mainloop()
