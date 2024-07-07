import sys
import time
import os
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit, QComboBox, QMessageBox, QFileDialog
from aes import AES, ECB, CBC, CTR
from Crypto.Random import get_random_bytes

class CryptoApp(QWidget):

    def __init__(self):
        super().__init__()
        self.file_extension = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle('AES Encryption/Decryption')
        self.setGeometry(600, 400, 400, 300)

        self.mode_label = QLabel('Mode:')
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(['ECB', 'CBC', 'CTR'])

        self.key_label = QLabel('Key Length:')
        self.key_combo = QComboBox()
        self.key_combo.addItems(['128', '192', '256'])

        self.input_label = QLabel('Input File:')
        self.input_edit = QLineEdit()
        self.input_btn = QPushButton('Browse')
        self.input_btn.clicked.connect(self.browse_input)

        self.encrypt_btn = QPushButton('Encrypt')
        self.encrypt_btn.clicked.connect(self.encrypt_file)

        self.decrypt_btn = QPushButton('Decrypt')
        self.decrypt_btn.clicked.connect(self.decrypt_file)

        layout = QVBoxLayout()
        layout.addWidget(self.mode_label)
        layout.addWidget(self.mode_combo)
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_combo)
        layout.addWidget(self.input_label)
        layout.addWidget(self.input_edit)
        layout.addWidget(self.input_btn)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.decrypt_btn)

        self.setLayout(layout)

    def browse_input(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Choose Input File', '', 'All Files (*)')
        if file_name:
            self.input_edit.setText(file_name)
            self.file_extension = self.input_type(file_name)


    def input_type(self, file):
        file_type = file.split('.')[-1]
        file_format = None
        if file_type in ['txt', 'pdf', 'doc', 'docx']: 
            file_format = 'txt'
        elif file_type in ['jpg', 'jpeg', 'png', 'avif', 'gif']:
            file_format = 'png'
        elif file_type in ['wav', 'mp3', 'm4a']:
            file_format = 'wav'
        elif file_type in ['mp4', 'mov', 'avi']:
            file_format = 'mp4'
        return file_format

    def encrypt_file(self):
        input_file = self.input_edit.text()
        mode = self.mode_combo.currentText()
        key_length = self.key_combo.currentText()

        if not input_file:
            QMessageBox.warning(self, 'Warning', 'Please choose input file.')
            return
        
        key = bytes.hex(os.urandom(int(key_length) // 8))
        aes = AES(key, int(key_length))

        with open('key.txt', 'w') as file:
            file.write(key)

        output_encrypted_file = input_file.split(".")[0] + '_encrypted.' + self.file_extension

        # output_encrypted_txt_representation = input_file.split(".")[0] + 'output_encrypted_txt_representation.txt'

        cipher = None
        if mode == 'ECB':
            cipher = ECB(aes)
        elif mode == 'CBC':
            cipher = CBC(aes, 16)
        elif mode == 'CTR':
            cipher = CTR(aes)

        try:
            enc_start_time = time.time()  # Encryption Start time
            cipher.cipher(input_file, output_encrypted_file)
            enc_end_time = time.time()  # Encryption End time

            enc_time = enc_end_time - enc_start_time
            data_size = os.path.getsize(input_file)       # Size of data in bytes
            enc_throughput = (data_size / 1024) / enc_time             # Throughput in kilobytes per second
            print("\nenc_time (sec):", enc_time)
            print("\tdata_size (kb):", data_size/1024)
            print("\tenc_throughput (kb/s):", enc_throughput)

            QMessageBox.information(self, 'Encryption', 'Encryption completed successfully.')
            
            print('mode:', mode)
            print('key length:', key_length)
            print('key :', key)
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def decrypt_file(self):
        input_file = self.input_edit.text()
        mode = self.mode_combo.currentText()
        key_length = self.key_combo.currentText()

        if not input_file:
            QMessageBox.warning(self, 'Warning', 'Please choose input file.')
            return

        if self.file_extension is None:
            QMessageBox.warning(self, 'Error', 'File extension not recognized.')
            return

        key = self.read_key()
        if not key:
            QMessageBox.warning(self, 'Error', 'Key file not found. Cannot decrypt without key.')
            return

        aes = AES(key, int(key_length))
        decipher = None

        if mode == 'ECB':
            decipher = ECB(aes)
        elif mode == 'CBC':
            decipher = CBC(aes, 16)
        elif mode == 'CTR':
            decipher = CTR(aes)

        output_decrypted_file = input_file.split(".")[0] + '_decrypted.' + self.file_extension

        # output_decrypted_txt_representation = input_file.split(".")[0] + 'output_decrypted_txt_representation.txt'

        try:
            dec_start_time = time.time()  # Decryption Start time
            decipher.decipher(input_file, output_decrypted_file)
            dec_end_time = time.time()  # Decryption Start time

            dec_time = dec_end_time - dec_start_time
            
            data_size = os.path.getsize(input_file)       # Size of data in bytes
            dec_throughput = (data_size / 1024) / dec_time             # Throughput in bytes per second
            print("\ndec_time (sec):", dec_time)
            print("\tdata_size (kb):", data_size/1024)
            print("\tdec_throughput (kb/s):", dec_throughput)

            QMessageBox.information(self, 'Decryption', 'Decryption completed successfully.')

            print('mode:', mode)
            print('key length:', key_length)
            print('key :', key)
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))


    def read_key(self):
        try:
            with open("key.txt", "rb") as f:
                return f.read()  
        except FileNotFoundError:
            return None
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec_())
