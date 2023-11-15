import tkinter as tk
from tkinter import filedialog, messagebox
import pyaes
import os
import time


class ECB:
    def __init__(self, key):
        self.key = key

    def pad_data(self, data, block_size):
        padding_length = block_size - len(data) % block_size
        return data + bytes([padding_length] * padding_length)

    def unpad_data(self, data):
        padding_length = data[-1]
        return data[:-padding_length]

    def encrypt_ecb(self, data):
        block_size = len(self.key)
        padded_data = self.pad_data(data, block_size)

        aes = pyaes.AES(self.key)

        encrypted_data = b""
        for i in range(0, len(padded_data), block_size):
            block = padded_data[i : i + block_size]
            encrypted_block = aes.encrypt(block)
            encrypted_data += encrypted_block

        return encrypted_data

    def decrypt_ecb(self, data):
        block_size = len(self.key)

        aes = pyaes.AES(self.key)

        decrypted_data = b""
        for i in range(0, len(data), block_size):
            block = data[i : i + block_size]
            decrypted_block = aes.decrypt(block)
            decrypted_data += decrypted_block

        return self.unpad_data(decrypted_data)


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Cipher")
        self.cipher = ECB()

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
