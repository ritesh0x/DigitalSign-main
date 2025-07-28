from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QComboBox, QTextEdit, QFileDialog, QProgressBar,
    QTabWidget, QSlider, QColorDialog, QGraphicsOpacityEffect, QMessageBox, QMenuBar, QMenu
)
from PySide6.QtGui import QFont, QColor, QPixmap, QIcon, QAction
from PySide6.QtCore import Qt, QPropertyAnimation, QRect, QEasingCurve
from PyPDF2 import PdfReader, PdfWriter
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

####################################
# Cryptographic Signature Manager  #
####################################
class SignatureManager:
    """
    Manages cryptographic operations for digital signatures.
    
    Features:
      - Key generation (RSA or DSA)
      - Signing of messages
      - Verification of signatures
      - Exporting keys to PEM format files
      - Loading keys from PEM format files
    """
    def __init__(self, algorithm="RSA"):
        """
        Initializes the SignatureManager with a specified algorithm.
        
        :param algorithm: 'RSA' or 'DSA' to choose the signing algorithm.
        """
        self.algorithm = algorithm
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """
        Generates a public-private key pair based on the selected algorithm.
        """
        if self.algorithm == "RSA":
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
        elif self.algorithm == "DSA":
            self.private_key = dsa.generate_private_key(
                key_size=2048, backend=default_backend()
            )
        self.public_key = self.private_key.public_key()

    def export_keys(self, private_path: str, public_path: str):
        """
        Exports the current key pair to PEM files.
        
        :param private_path: Path to save the private key.
        :param public_path: Path to save the public key.
        :raises ValueError: If keys have not been generated.
        """
        if self.private_key is None:
            raise ValueError("Keys have not been generated.")
        # Export private key in PEM format
        pem_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(private_path, "wb") as f:
            f.write(pem_private)
        # Export public key in PEM format
        pem_public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_path, "wb") as f:
            f.write(pem_public)

    def load_private_key(self, private_path: str):
        """
        Loads a private key from a PEM file.
        
        :param private_path: Path to the private key file.
        """
        with open(private_path, "rb") as f:
            pem_data = f.read()
        self.private_key = serialization.load_pem_private_key(
            pem_data, password=None, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def load_public_key(self, public_path: str):
        """
        Loads a public key from a PEM file.
        
        :param public_path: Path to the public key file.
        """
        with open(public_path, "rb") as f:
            pem_data = f.read()
        self.public_key = serialization.load_pem_public_key(
            pem_data, backend=default_backend()
        )

    def hash_message(self, message: bytes) -> bytes:
        """
        Computes a SHA-256 hash of the input message.
        
        :param message: Message in bytes.
        :return: SHA-256 hash digest of the message.
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        return digest.finalize()

    def sign(self, message: bytes) -> bytes:
        """
        Signs a message using the generated or loaded private key.
        
        :param message: Message in bytes.
        :return: Digital signature in bytes.
        """
        if self.private_key is None or self.public_key is None:
            self.generate_keys()
        hashed = self.hash_message(message)
        if self.algorithm == "RSA":
            return self.private_key.sign(
                hashed, padding.PKCS1v15(), hashes.SHA256()
            )
        elif self.algorithm == "DSA":
            return self.private_key.sign(hashed, hashes.SHA256())

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verifies a signature for a given message using the public key.
        
        :param message: Original message in bytes.
        :param signature: Digital signature in bytes.
        :return: True if the signature is valid, False otherwise.
        :raises ValueError: If no public key is available.
        """
        if self.public_key is None:
            raise ValueError("Public key not available. Sign a message first or load keys.")
        hashed = self.hash_message(message)
        try:
            if self.algorithm == "RSA":
                self.public_key.verify(
                    signature, hashed, padding.PKCS1v15(), hashes.SHA256()
                )
            elif self.algorithm == "DSA":
                self.public_key.verify(signature, hashed, hashes.SHA256())
            return True
        except Exception:
            return False

####################################
# Digital Signature Widget (UI)  #
####################################
class DigitalSignatureWidget(QWidget):
    """
    Provides a GUI for signing and verifying messages/PDF files as well as managing keys.
    
    This widget contains three tabs:
      - Sign Message/File: Allows users to sign text messages or PDF files.
      - Verify Signature: Allows users to verify signatures for messages.
      - Key Management: Offers options to load or export key pairs.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.signature_manager = None  # Instantiate when needed

        layout = QVBoxLayout(self)
        self.tabWidget = QTabWidget()
        layout.addWidget(self.tabWidget)

        # Create tabs for signing, verifying, and key management
        self.sign_tab = QWidget()
        self.verify_tab = QWidget()
        self.keys_tab = QWidget()
        self.tabWidget.addTab(self.sign_tab, "🔒 Sign Message/File")
        self.tabWidget.addTab(self.verify_tab, "Verify Signature")
        self.tabWidget.addTab(self.keys_tab, "Key Management")

        self.setup_sign_tab()
        self.setup_verify_tab()
        self.setup_keys_tab()

        # Progress bar to indicate operation status
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

    def setup_sign_tab(self):
        """
        Sets up the UI components for the sign tab.
        """
        layout = QVBoxLayout(self.sign_tab)
        # Optional: Display an image
        try:
            image_label = QLabel()
            pixmap = QPixmap("Digital-Signature-in-Cryptography-.jpg")
            scaled_pixmap = pixmap.scaled(400, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            image_label.setPixmap(scaled_pixmap)
            layout.addWidget(image_label)
        except Exception:
            pass

        # Algorithm selection combo box
        layout.addWidget(QLabel("Select Digital Signature Algorithm:"))
        self.sign_algo_combo = QComboBox()
        self.sign_algo_combo.addItems(["RSA", "DSA"])
        layout.addWidget(self.sign_algo_combo)

        # Input for the message to be signed
        layout.addWidget(QLabel("Enter the message to be signed:"))
        self.sign_message_input = QLineEdit()
        self.sign_message_input.setToolTip("Enter the message that you want to sign.")
        layout.addWidget(self.sign_message_input)

        # Buttons for PDF signing and conversion
        self.sign_pdf_button = QPushButton("Sign PDF File")
        self.sign_pdf_button.clicked.connect(self.sign_pdf_file)
        layout.addWidget(self.sign_pdf_button)

        self.pdf_to_hex_button = QPushButton("Convert PDF to Hex")
        self.pdf_to_hex_button.setToolTip("Convert a PDF file into its hexadecimal representation.")
        self.pdf_to_hex_button.clicked.connect(self.convert_pdf_to_hex)
        layout.addWidget(self.pdf_to_hex_button)

        self.hex_to_pdf_button = QPushButton("Convert Hex to PDF")
        self.hex_to_pdf_button.setToolTip("Convert a hex file back into a PDF file.")
        self.hex_to_pdf_button.clicked.connect(self.convert_hex_to_pdf)
        layout.addWidget(self.hex_to_pdf_button)

        # Button to sign the message
        self.sign_button = QPushButton("Sign Message")
        self.sign_button.clicked.connect(self.sign_message)
        layout.addWidget(self.sign_button)

        # Clear fields button
        self.clear_sign_button = QPushButton("Clear Fields")
        self.clear_sign_button.clicked.connect(self.clear_sign_fields)
        layout.addWidget(self.clear_sign_button)

        # Output display area for results
        layout.addWidget(QLabel("Output:"))
        self.sign_output_display = QTextEdit()
        self.sign_output_display.setReadOnly(True)
        layout.addWidget(self.sign_output_display)

    def setup_verify_tab(self):
        """
        Sets up the UI components for the verify tab.
        """
        layout = QVBoxLayout(self.verify_tab)
        layout.addWidget(QLabel("Select Digital Signature Algorithm:"))
        self.verify_algo_combo = QComboBox()
        self.verify_algo_combo.addItems(["RSA", "DSA"])
        layout.addWidget(self.verify_algo_combo)

        # Input for the message whose signature is to be verified
        layout.addWidget(QLabel("Enter the message to verify:"))
        self.verify_message_input = QLineEdit()
        self.verify_message_input.setToolTip("Enter the message you want to verify.")
        layout.addWidget(self.verify_message_input)

        # Input for the Base64-encoded signature
        layout.addWidget(QLabel("Enter the signature to verify (Base64):"))
        self.verify_signature_input = QLineEdit()
        self.verify_signature_input.setToolTip("Enter the signature in Base64 format.")
        layout.addWidget(self.verify_signature_input)

        # Button to verify the signature
        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.verify_button)

        # Clear fields button for verification tab
        self.clear_verify_button = QPushButton("Clear Fields")
        self.clear_verify_button.clicked.connect(self.clear_verify_fields)
        layout.addWidget(self.clear_verify_button)

        # Output display area for verification results
        layout.addWidget(QLabel("Output:"))
        self.verify_output_display = QTextEdit()
        self.verify_output_display.setReadOnly(True)
        layout.addWidget(self.verify_output_display)

    def setup_keys_tab(self):
        """
        Sets up the UI components for key management.
        """
        layout = QVBoxLayout(self.keys_tab)
        layout.addWidget(QLabel("Key Management", alignment=Qt.AlignCenter))

        # Button to load a private key from a file
        self.load_private_button = QPushButton("Load Private Key")
        self.load_private_button.clicked.connect(self.load_private_key)
        layout.addWidget(self.load_private_button)

        # Button to load a public key from a file
        self.load_public_button = QPushButton("Load Public Key")
        self.load_public_button.clicked.connect(self.load_public_key)
        layout.addWidget(self.load_public_button)

        # Button to export the current keys to files
        self.save_keys_button = QPushButton("Export Keys")
        self.save_keys_button.clicked.connect(self.export_keys)
        layout.addWidget(self.save_keys_button)

        layout.addStretch()

    def clear_sign_fields(self):
        """
        Clears the fields in the sign tab.
        """
        self.sign_message_input.clear()
        self.sign_output_display.clear()

    def clear_verify_fields(self):
        """
        Clears the fields in the verify tab.
        """
        self.verify_message_input.clear()
        self.verify_signature_input.clear()
        self.verify_output_display.clear()

    def sign_message(self):
        """
        Signs the input message using the selected algorithm and displays the Base64 signature.
        """
        self.progress_bar.setValue(10)
        algorithm = self.sign_algo_combo.currentText()
        message_text = self.sign_message_input.text()
        if not message_text:
            self._show_error("Please enter a message to sign.")
            self.progress_bar.setValue(0)
            return

        message = message_text.encode()
        if self.signature_manager is None or self.signature_manager.algorithm != algorithm:
            self.signature_manager = SignatureManager(algorithm)
        signature = self.signature_manager.sign(message)
        b64_signature = base64.b64encode(signature).decode()
        self.sign_output_display.setText(f"{algorithm} Signature (Base64):\n{b64_signature}")
        self.progress_bar.setValue(100)

    def sign_pdf_file(self):
        """
        Signs a PDF file by adding a metadata field for signature.
        """
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select a PDF File to Sign", filter="PDF Files (*.pdf)"
        )
        if not file_name:
            return
        try:
            reader = PdfReader(file_name)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.add_metadata({"/Signature": "Signed by AdvancedDigitalSignatureApp"})
            output_file = file_name.replace(".pdf", "_signed.pdf")
            with open(output_file, "wb") as output_pdf:
                writer.write(output_pdf)
            self.sign_output_display.setText(f"PDF signed successfully: {output_file}")
        except Exception as e:
            self._show_error(f"Error signing PDF: {str(e)}")

    def convert_pdf_to_hex(self):
        """
        Converts a PDF file to its hexadecimal representation and saves it.
        """
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select a PDF File to Convert", filter="PDF Files (*.pdf)"
        )
        if not file_name:
            return
        try:
            with open(file_name, "rb") as pdf_file:
                pdf_bytes = pdf_file.read()
            hex_data = pdf_bytes.hex()
            save_file, _ = QFileDialog.getSaveFileName(
                self, "Save Hex Output", file_name.replace(".pdf", "_hex.txt"), filter="Text Files (*.txt)"
            )
            if save_file:
                with open(save_file, "w") as hex_file:
                    hex_file.write(hex_data)
                self.sign_output_display.setText(f"Hex output saved to: {save_file}")
        except Exception as e:
            self._show_error(f"Error converting PDF to hex: {str(e)}")

    def convert_hex_to_pdf(self):
        """
        Converts a hex file back into a PDF file.
        """
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select a Hex File to Convert", filter="Text Files (*.txt *.hex)"
        )
        if not file_name:
            return
        try:
            with open(file_name, "r") as hex_file:
                hex_data = hex_file.read().strip()
            try:
                pdf_bytes = bytes.fromhex(hex_data)
            except ValueError:
                self._show_error("The file does not contain valid hex data.")
                return
            save_file, _ = QFileDialog.getSaveFileName(
                self, "Save PDF Output", file_name.replace("_hex.txt", "_restored.pdf"), filter="PDF Files (*.pdf)"
            )
            if save_file:
                with open(save_file, "wb") as pdf_file:
                    pdf_file.write(pdf_bytes)
                self.sign_output_display.setText(f"PDF restored successfully: {save_file}")
        except Exception as e:
            self._show_error(f"Error converting hex to PDF: {str(e)}")

    def verify_signature(self):
        """
        Verifies a digital signature for the given message.
        """
        self.progress_bar.setValue(10)
        algorithm = self.verify_algo_combo.currentText()
        message_text = self.verify_message_input.text()
        sig_b64 = self.verify_signature_input.text()
        if not message_text or not sig_b64:
            self._show_error("Please provide both a message and signature.")
            self.progress_bar.setValue(0)
            return
        try:
            signature = base64.b64decode(sig_b64)
        except Exception:
            self._show_error("Invalid Base64 signature format.")
            self.progress_bar.setValue(0)
            return

        message = message_text.encode()
        if self.signature_manager is None or self.signature_manager.algorithm != algorithm:
            self._show_error("No key pair found for this algorithm. Please sign a message or load keys first.")
            self.progress_bar.setValue(0)
            return

        valid = self.signature_manager.verify(message, signature)
        if valid:
            self.verify_output_display.setText(f"{algorithm} Signature is valid!")
        else:
            self.verify_output_display.setText(f"{algorithm} Signature verification failed!")
        self.progress_bar.setValue(100)

    def load_private_key(self):
        """
        Loads a private key from a PEM file.
        """
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select Private Key PEM File", filter="PEM Files (*.pem *.key)"
        )
        if not file_name:
            return
        try:
            algorithm = self.sign_algo_combo.currentText()
            if self.signature_manager is None or self.signature_manager.algorithm != algorithm:
                self.signature_manager = SignatureManager(algorithm)
            self.signature_manager.load_private_key(file_name)
            QMessageBox.information(self, "Key Loaded", "Private key loaded successfully.")
        except Exception as e:
            self._show_error(f"Error loading private key: {str(e)}")

    def load_public_key(self):
        """
        Loads a public key from a PEM file.
        """
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select Public Key PEM File", filter="PEM Files (*.pem *.key)"
        )
        if not file_name:
            return
        try:
            algorithm = self.verify_algo_combo.currentText()
            if self.signature_manager is None or self.signature_manager.algorithm != algorithm:
                self.signature_manager = SignatureManager(algorithm)
            self.signature_manager.load_public_key(file_name)
            QMessageBox.information(self, "Key Loaded", "Public key loaded successfully.")
        except Exception as e:
            self._show_error(f"Error loading public key: {str(e)}")

    def export_keys(self):
        """
        Exports the current key pair to PEM files.
        """
        if self.signature_manager is None:
            self._show_error("No keys available. Sign a message first to generate keys.")
            return
        private_file, _ = QFileDialog.getSaveFileName(
            self, "Export Private Key", "private_key.pem", filter="PEM Files (*.pem)"
        )
        public_file, _ = QFileDialog.getSaveFileName(
            self, "Export Public Key", "public_key.pem", filter="PEM Files (*.pem)"
        )
        if private_file and public_file:
            try:
                self.signature_manager.export_keys(private_file, public_file)
                QMessageBox.information(self, "Export Keys", "Keys exported successfully.")
            except Exception as e:
                self._show_error(f"Error exporting keys: {str(e)}")

    def _show_error(self, message: str):
        """
        Displays an error message using a message box.
        
        :param message: Error message to be displayed.
        """
        QMessageBox.critical(self, "Error", message)

    # Drag & drop events for file input in the sign tab
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                self.sign_message_input.setText(data.decode(errors='ignore'))
            except Exception as e:
                self._show_error(f"Error reading dropped file: {str(e)}")

####################################
#           Settings Widget        #
####################################
class SettingsWidget(QWidget):
    """
    Provides settings for customizing the application's appearance.
    
    Options include:
      - Switching between Dark and Light Mode
      - Selecting the font style and size
      - Choosing an accent color for highlights
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.init_ui()

    def init_ui(self):
        """
        Initializes the settings UI.
        """
        layout = QVBoxLayout(self)
        header = QLabel("Settings Panel")
        header.setFont(QFont("Arial", 18, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Screen mode selection
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Select Screen Mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Dark Mode", "Light Mode"])
        self.mode_combo.setToolTip("Choose between Dark Mode and Light Mode for the application.")
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        layout.addLayout(mode_layout)
        
        # Font style selection
        font_layout = QHBoxLayout()
        font_label = QLabel("Select Font Style:")
        self.font_combo = QComboBox()
        self.font_combo.addItems(["Arial", "Times New Roman", "Courier New", "Verdana"])
        self.font_combo.setToolTip("Choose your preferred font style for the application.")
        font_layout.addWidget(font_label)
        font_layout.addWidget(self.font_combo)
        layout.addLayout(font_layout)
        
        # Global font size slider
        size_layout = QHBoxLayout()
        size_label = QLabel("Global Font Size:")
        self.font_size_slider = QSlider(Qt.Horizontal)
        self.font_size_slider.setRange(8, 36)
        self.font_size_slider.setValue(12)
        self.font_size_slider.setToolTip("Adjust the global font size for the application pages.")
        size_layout.addWidget(size_label)
        size_layout.addWidget(self.font_size_slider)
        layout.addLayout(size_layout)
        
        # Accent color picker
        accent_layout = QHBoxLayout()
        accent_label = QLabel("Accent Color:")
        self.accent_color_button = QPushButton("Select Color")
        self.accent_color_button.setToolTip("Choose an accent color for highlights and buttons.")
        self.accent_color_button.clicked.connect(self.select_accent_color)
        accent_layout.addWidget(accent_label)
        accent_layout.addWidget(self.accent_color_button)
        layout.addLayout(accent_layout)
        
        # Preview label to display settings changes with animation
        self.preview_label = QLabel("Preview: The quick brown fox jumps over the lazy dog.")
        self.preview_label.setAlignment(Qt.AlignCenter)
        self.preview_label.setFont(QFont(self.font_combo.currentText(), self.font_size_slider.value()))
        layout.addWidget(self.preview_label)
        self.opacity_effect = QGraphicsOpacityEffect(self.preview_label)
        self.preview_label.setGraphicsEffect(self.opacity_effect)
        
        # Button to apply the settings
        self.apply_button = QPushButton("Apply Settings")
        self.apply_button.setToolTip("Apply settings with a smooth animated transition.")
        self.apply_button.clicked.connect(self.apply_settings)
        layout.addWidget(self.apply_button)
        
        layout.addStretch()
        self.font_combo.currentTextChanged.connect(self.animate_preview)
        self.font_size_slider.valueChanged.connect(self.animate_preview)

    def select_accent_color(self):
        """
        Opens a color dialog for selecting an accent color.
        """
        color = QColorDialog.getColor()
        if color.isValid():
            self.accent_color = color
            self.preview_label.setStyleSheet(f"color: {color.name()};")
            self.animate_preview()

    def animate_preview(self):
        """
        Animates the preview label to show font and color changes.
        """
        fade_out = QPropertyAnimation(self.opacity_effect, b"opacity")
        fade_out.setDuration(80)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.0)
        fade_out.setEasingCurve(QEasingCurve.InOutQuad)
        
        fade_in = QPropertyAnimation(self.opacity_effect, b"opacity")
        fade_in.setDuration(80)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.setEasingCurve(QEasingCurve.InOutQuad)
        
        def update_preview():
            new_font = QFont(self.font_combo.currentText(), self.font_size_slider.value())
            self.preview_label.setFont(new_font)
        
        fade_out.finished.connect(update_preview)
        fade_out.finished.connect(fade_in.start)
        fade_out.start()
        
        original_rect = self.preview_label.geometry()
        anim = QPropertyAnimation(self.preview_label, b"geometry")
        anim.setDuration(160)
        anim.setStartValue(original_rect)
        anim.setKeyValueAt(0.5, QRect(original_rect.x(), original_rect.y() - 5, original_rect.width(), original_rect.height()))
        anim.setEndValue(original_rect)
        anim.setEasingCurve(QEasingCurve.OutBounce)
        anim.start()

    def apply_settings(self):
        """
        Applies the selected settings to the main application window.
        """
        mode = self.mode_combo.currentText()
        if mode == "Dark Mode":
            new_stylesheet = "background-color: #2d2d2d; color: white;"
        else:
            new_stylesheet = "background-color: white; color: black;"
        if self.parent_window:
            self.parent_window.setStyleSheet(new_stylesheet)
            new_font = QFont(self.font_combo.currentText(), self.font_size_slider.value())
            self.parent_window.setFont(new_font)
            for child in self.parent_window.findChildren(QWidget):
                child.setFont(new_font)

####################################
#           About Widget           #
####################################
class AboutWidget(QWidget):
    """
    Displays information about the application.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        
        title = QLabel("Digital Signature Application")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(title)

        version = QLabel("Project Version: 1.1 Advanced")
        version.setFont(QFont("Arial", 14))
        layout.addWidget(version)

        description = QTextEdit()
        description_text = (
          """
🔹 ABOUT: - Secure Digital Signature Implementation 🔹

🛡️ This script provides a robust digital signature mechanism to ensure the integrity ✅ and authenticity 🔏 
of files or messages. Designed with strong cryptographic principles, it enables secure 🔑 signing and 
verification to protect against tampering.

✨ Key Features:
✅ Secure digital signing of messages or files 📜
✅ Verification of signatures to prevent tampering 🔍
✅ Integration with cryptographic libraries for enhanced security 🔐
✅ Efficient and lightweight design for easy deployment ⚡
✅ Reliable protection against unauthorized modifications 🚨

👨‍💻 Developed by: Cyber Intern  
🛠️ Version: 1.1  
📜 License: Open Source / Custom (Modify as needed)  
"""

        )
        description.setPlainText(description_text)
        description.setFont(QFont("Arial", 14))
        description.setReadOnly(True)
        layout.addWidget(description)

        self.animation = QPropertyAnimation(title, b"geometry")
        self.animation.setDuration(2000)
        self.animation.setStartValue(QRect(0, 0, 0, 0))
        self.animation.setEndValue(QRect(0, 0, 300, 50))
        self.animation.start()

####################################
#            Main App              #
####################################
class MainApp(QMainWindow):
    """
    Main application window that integrates the digital signature widget, settings, and about information.
    
    Also creates a menu bar with basic File and Help options.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Digital Signature Application")
        self.setGeometry(50, 50, 1100, 850)

        # Create a menu bar for future advanced options
        self._create_menu_bar()

        self.central_tabs = QTabWidget()
        self.setCentralWidget(self.central_tabs)

        # Initialize main components
        self.signature_page = DigitalSignatureWidget()
        self.settings_page = SettingsWidget(self)
        self.about_page = AboutWidget()

        self.signature_page.setMinimumSize(800, 600)
        self.settings_page.setMinimumSize(800, 600)

        # Add tabs to the central widget
        self.central_tabs.addTab(self.signature_page, "Digital Signature")
        self.central_tabs.addTab(self.settings_page, "Settings")
        self.central_tabs.addTab(self.about_page, "About")

    def _create_menu_bar(self):
        """
        Creates a menu bar with File and Help menus.
        """
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)
        file_menu = QMenu("File", self)
        menu_bar.addMenu(file_menu)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        help_menu = QMenu("Help", self)
        menu_bar.addMenu(help_menu)
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

    def show_about_dialog(self):
        """
        Displays an about dialog with application information.
        """
        QMessageBox.information(self, "About", "Advanced Digital Signature Application\nVersion 1.1 Advanced")

if __name__ == "__main__":
    app = QApplication([])
    window = MainApp()
    window.show()
    app.exec()
