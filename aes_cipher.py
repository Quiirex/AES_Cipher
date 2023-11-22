import tkinter as tk
from tkinter import filedialog, messagebox
import pyaes
import os
import time


class PKCS7Padding:  # PKCS#7 shema
    def pad_data(data, block_size):
        # Izračunamo dolžino polnila, ki je enaka razliki med velikostjo bloka in ostankom dolžine podatkov deljeno z velikostjo bloka
        padding_length = block_size - len(data) % block_size
        return data + bytes([padding_length] * padding_length)

    def unpad_data(data):
        # Dolžina polnila je enaka vrednosti zadnjega bajta
        padding_length = data[-1]
        # Preverimo, ali je polnilo veljavno. Če ni, sprožimo napako
        if data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid padding!")
        return data[:-padding_length]


class ECB:
    def __init__(self, key):
        self.key = key
        self.block_size = 16
        self.aes = pyaes.AES(self.key)

    def _process_data(self, data, operation):
        print(f"{operation.capitalize()}ing with ECB mode..")
        processed_data = b""
        for i in range(0, len(data), self.block_size):
            # Izbor bloka podatkov
            block = data[i : i + self.block_size]
            # Obdelava bloka podatkov
            processed_block = getattr(self.aes, operation)(block)
            processed_data += bytes(processed_block)
        return processed_data

    def encrypt(self, data):
        # Dodajanje polnila k podatkom
        padded_data = PKCS7Padding.pad_data(data, self.block_size)
        # Šifriranje podatkov
        return self._process_data(padded_data, "encrypt")

    def decrypt(self, data):
        # Dešifriranje podatkov
        decrypted_data = self._process_data(data, "decrypt")
        # Odstranjevanje polnila iz dešifriranih podatkov
        return PKCS7Padding.unpad_data(decrypted_data)


class CBC:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.block_size = 16
        self.aes = pyaes.AES(self.key)

    def _process_data(self, data, operation):
        print(f"{operation.capitalize()}ing with CBC mode..")
        processed_data = b""
        # Začetni blok za XOR operacijo
        previous_block = self.iv
        for i in range(0, len(data), self.block_size):
            # Izbor bloka podatkov
            block = data[i : i + self.block_size]
            # Če šifriramo, izvedemo XOR operacijo med trenutnim blokom in prejšnjim blokom pred šifriranjem
            if operation == "encrypt":
                block = bytes(
                    [block[j] ^ previous_block[j] for j in range(self.block_size)]
                )
                # Šifriranje bloka
                processed_block = self.aes.encrypt(block)
                # Nastavimo trenutni šifriran blok kot prejšnji blok za naslednjo iteracijo
                previous_block = processed_block
            else:
                # Dešifriranje bloka
                processed_block = self.aes.decrypt(block)
                # Izvedemo XOR operacijo med dešifriranim blokom in prejšnjim blokom
                processed_block = bytes(
                    [
                        processed_block[j] ^ previous_block[j]
                        for j in range(self.block_size)
                    ]
                )
                # Nastavimo trenutni nešifriran blok kot prejšnji blok za naslednjo iteracijo
                previous_block = block
            processed_data += bytes(processed_block)
        return processed_data

    def encrypt(self, data):
        # Dodajanje polnila k podatkom
        padded_data = PKCS7Padding.pad_data(data, self.block_size)
        # Šifriranje podatkov
        return self._process_data(padded_data, "encrypt")

    def decrypt(self, data):
        # Dešifriranje podatkov
        decrypted_data = self._process_data(data, "decrypt")
        # Odstranjevanje polnila iz dešifriranih podatkov
        return PKCS7Padding.unpad_data(decrypted_data)


class CTR:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        self.block_size = 16
        self.aes = pyaes.AES(self.key)

    def _process_data(self, data, operation):
        print(f"{operation.capitalize()}ing with CTR mode..")
        counter = int.from_bytes(self.nonce, byteorder="big")
        processed_data = b""
        for i in range(0, len(data), self.block_size):
            # Pretvorba števca v blok bajtov
            counter_block = counter.to_bytes(self.block_size, byteorder="big")
            counter += 1
            # Šifriranje števca za ustvarjanje ključnega toka
            keystream = self.aes.encrypt(counter_block)
            # Izbor bloka podatkov
            block = data[i : i + self.block_size]
            # Izvedba XOR operacije med blokom podatkov in tokom ključev
            processed_block = bytes(
                [block[j] ^ keystream[j] for j in range(len(block))]
            )
            processed_data += processed_block
        return processed_data

    def encrypt(self, data):
        return self._process_data(data, "encrypt")

    def decrypt(self, data):
        return self._process_data(data, "decrypt")


class CCM:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.block_size = 16
        self.aes = pyaes.AES(self.key)

    def _process_data(self, data, operation):
        print(f"{operation.capitalize()}ing with CCM mode..")
        counter = int.from_bytes(self.iv, byteorder="big")
        processed_data = b""
        for i in range(0, len(data), self.block_size):
            # Pretvorba števca v blok bajtov
            counter_block = counter.to_bytes(self.block_size, byteorder="big")
            counter += 1
            # Šifriranje bloka števca za ustvarjanje toka ključev
            keystream = self.aes.encrypt(counter_block)
            # Izbor bloka podatkov
            block = data[i : i + self.block_size]
            # Izvedba XOR operacije med blokom podatkov in tokom ključev
            processed_block = bytes(
                [block[j] ^ keystream[j] for j in range(len(block))]
            )
            processed_data += processed_block
        return processed_data

    def _cbc_mac(self, data):
        mac = b"\x00" * self.block_size
        for i in range(0, len(data), self.block_size):
            # Izbor bloka podatkov
            block = data[i : i + self.block_size]
            # Izvedba XOR operacije med trenutno MAC vrednostjo in blokom podatkov
            mac = bytes([mac[j] ^ block[j] for j in range(self.block_size)])
            # Šifriranje trenutne MAC vrednosti
            mac = self.aes.encrypt(mac)
        return mac

    def encrypt(self, data):
        # Dodajanje polnila k podatkom
        padded_data = PKCS7Padding.pad_data(data, self.block_size)
        # Šifriranje podatkov
        ciphertext = self._process_data(padded_data, "encrypt")
        # Izračun MAC vrednosti šifriranih podatkov
        mac = bytes(self._cbc_mac(ciphertext))
        return ciphertext + mac

    def decrypt(self, data):
        # Izbor šifriranih podatkov in MAC vrednosti iz vhodnih podatkov
        ciphertext = data[: -self.block_size]
        mac = bytes(data[-self.block_size :])
        # Preverjanje veljavnosti MAC vrednosti
        if mac != bytes(self._cbc_mac(ciphertext)):
            raise ValueError("Invalid MAC!")
        # Dešifriranje podatkov
        return self._process_data(ciphertext, "decrypt")


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Cipher")

        self.loaded_file_content = None
        self.encrypted_content = None
        self.decrypted_content = None
        self.encryption_mode = True  # True za šifriranje, False za dešifriranje

        self.mode = None
        self.key = None
        self.iv = None
        self.nonce = None
        self.key_size = 16  # 128-bitni ključ
        self.iv_size = 16  # 128-bitni inicializacijski vektor
        self.nonce_size = 8  # 64-bitni nonce

        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=0, column=0, padx=20, pady=20)

        self.text_label = tk.Label(
            self.input_frame, text="Input:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=0, column=0)
        self.loaded_file_label = tk.Label(
            self.input_frame, text="<No file loaded>", width=35
        )
        self.loaded_file_label.grid(row=0, column=1)

        self.text_label = tk.Label(
            self.input_frame, text="Key:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=1, column=0)
        self.key_label = tk.Label(self.input_frame, text="<No key loaded>", width=35)
        self.key_label.grid(row=1, column=1)

        self.text_label = tk.Label(
            self.input_frame, text="IV:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=2, column=0)
        self.iv_label = tk.Label(self.input_frame, text="<No IV loaded>", width=35)
        self.iv_label.grid(row=2, column=1)

        self.text_label = tk.Label(
            self.input_frame, text="Nonce:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=3, column=0)
        self.nonce_label = tk.Label(
            self.input_frame, text="<No nonce loaded>", width=35
        )
        self.nonce_label.grid(row=3, column=1)

        self.output_label = tk.Label(
            self.input_frame, text="Output:", width=8, font=("Helvetica", 13, "bold")
        )
        self.output_label.grid(row=4, column=0)
        self.output_file_label = tk.Label(
            self.input_frame, text="<Encrypt/Decrypt a file..>", width=35
        )
        self.output_file_label.grid(row=4, column=1)

        self.mode_label = tk.Label(
            self.input_frame, text="Mode:", width=8, font=("Helvetica", 13, "bold")
        )
        self.mode_label.grid(row=5, column=0)
        self.mode = tk.StringVar()
        self.mode_menu = tk.OptionMenu(
            self.input_frame,
            self.mode,
            "ECB",
            "CBC",
            "CTR",
            "CCM",
            command=self.set_mode,
        )
        self.mode_menu.grid(row=5, column=1, pady=5)

        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=4, column=0, padx=20, pady=20)

        self.load_file_button = tk.Button(
            self.button_frame,
            text="Load file..",
            command=self.load_file,
            width=8,
        )
        self.load_file_button.grid(row=0, column=0, pady=10)

        self.generate_key_button = tk.Button(
            self.button_frame, text="Generate key", command=self.generate_key, width=8
        )
        self.generate_key_button.grid(row=1, column=0)

        self.upload_key_button = tk.Button(
            self.button_frame, text="Load key..", command=self.load_key, width=8
        )
        self.upload_key_button.grid(row=1, column=1)

        self.generate_iv_button = tk.Button(
            self.button_frame,
            text="Generate IV",
            command=self.generate_iv,
            width=8,
        )
        self.generate_iv_button.grid(row=2, column=0)

        self.load_iv_button = tk.Button(
            self.button_frame, text="Load IV..", command=self.load_iv, width=8
        )
        self.load_iv_button.grid(row=2, column=1)

        self.generate_iv_button = tk.Button(
            self.button_frame,
            text="Generate nonce",
            command=self.generate_nonce,
            width=8,
        )
        self.generate_iv_button.grid(row=3, column=0)

        self.load_iv_button = tk.Button(
            self.button_frame, text="Load nonce..", command=self.load_nonce, width=8
        )
        self.load_iv_button.grid(row=3, column=1)

        self.encrypt_button = tk.Button(
            self.button_frame, text="Encrypt", command=self.encrypt_file, width=8
        )
        self.encrypt_button.grid(row=4, column=0, pady=10)

        self.decrypt_button = tk.Button(
            self.button_frame, text="Decrypt", command=self.decrypt_file, width=8
        )
        self.decrypt_button.grid(row=4, column=1, pady=10)

    def set_mode(self, mode):
        if mode == "ECB":
            self.mode = ECB(self.key)
        elif mode == "CBC":
            self.mode = CBC(self.key, self.iv)
        elif mode == "CTR":
            self.mode = CTR(self.key, self.nonce)
        elif mode == "CCM":
            self.mode = CCM(self.key, self.iv)

    def generate_iv(self):
        self.iv = os.urandom(self.iv_size)
        self.iv_label.config(text="IV generated and loaded.")
        self.save_iv()

    def save_iv(self):
        iv = self.iv
        if iv:
            file_path = filedialog.asksaveasfilename(
                filetypes=[("Text Files", "*.txt")]
            )
            with open(file_path, "wb") as file:
                file.write(iv)
        else:
            messagebox.showerror("Error", "No IV generated to save!")

    def load_iv(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "rb") as file:
                self.iv = file.read()
                self.iv_label.config(text="IV loaded.")
        else:
            messagebox.showerror("Error", "No IV loaded!")

    def generate_nonce(self):
        self.nonce = os.urandom(self.nonce_size)
        self.nonce_label.config(text="Nonce generated and loaded.")
        self.save_nonce()

    def save_nonce(self):
        nonce = self.nonce
        if nonce:
            file_path = filedialog.asksaveasfilename(
                filetypes=[("Text Files", "*.txt")]
            )
            with open(file_path, "wb") as file:
                file.write(nonce)
        else:
            messagebox.showerror("Error", "No nonce generated to save!")

    def load_nonce(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "rb") as file:
                self.nonce = file.read()
                self.nonce_label.config(text="Nonce loaded.")
        else:
            messagebox.showerror("Error", "No nonce loaded!")

    def generate_key(self):
        self.key = os.urandom(self.key_size)
        self.key_label.config(text="Key generated and loaded.")
        self.save_key()

    def save_key(self):
        if self.key:
            file_path = filedialog.asksaveasfilename(
                filetypes=[("Text Files", "*.txt")]
            )
            with open(file_path, "wb") as file:
                file.write(self.key)
        else:
            messagebox.showerror("Error", "No key generated to save!")

    def load_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "rb") as file:
                self.key = file.read()
                self.key_label.config(text="Key loaded.")
        else:
            messagebox.showerror("Error", "No key loaded!")

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
            if self.key is None:
                messagebox.showerror("Error", "No key loaded!")
                return
            if (
                isinstance(self.mode, CBC) or isinstance(self.mode, CCM)
            ) and self.iv is None:
                messagebox.showerror("Error", "No IV loaded!")
                return
            if (isinstance(self.mode, CTR)) and self.nonce is None:
                messagebox.showerror("Error", "No nonce loaded!")
                return
            start = time.time()
            print(f"Starting encryption..")
            self.encrypted_content = self.mode.encrypt(self.loaded_file_content)
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
            if self.key is None:
                messagebox.showerror("Error", "No key loaded!")
                return
            if (
                isinstance(self.mode, CBC) or isinstance(self.mode, CCM)
            ) and self.iv is None:
                messagebox.showerror("Error", "No IV loaded!")
                return
            if (isinstance(self.mode, CTR)) and self.nonce is None:
                messagebox.showerror("Error", "No nonce loaded!")
                return
            start = time.time()
            print(f"Starting decryption..")
            self.decrypted_content = self.mode.decrypt(self.loaded_file_content)
            print(f"Decryption finished!")
            end = time.time()
            decryption_speed = len(self.loaded_file_content) / (
                1024 * 1024 * (end - start)
            )
            print(f"Decryption speed: {round(decryption_speed, 2)} MB/s")
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
