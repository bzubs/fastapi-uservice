from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.utils import ImageReader
from datetime import datetime
import hashlib
import base64
import json
import io
import qrcode
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os
from .schemas import GenerateRequest, Payload
from dotenv import load_dotenv

load_dotenv()


class CertificateGenerator:
    def __init__(self):
        private_key_pem = os.getenv("PRIVATE_KEY_PEM")
        if not private_key_pem:
            raise RuntimeError("Missing PRIVATE_KEY_PEM env variable")

        key = load_pem_private_key(private_key_pem.encode(), password=None)

        # Ensure key is ECDSA
        if not hasattr(key, 'sign') or not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError("Loaded private key is not an EC key. Please check your environment variable.")

        self.private_key = key
        self.public_key = self.private_key.public_key()

        # Modern color scheme
        self.primary_blue = HexColor("#0f4c81")
        self.accent_blue = HexColor("#3b82f6")
        self.soft_gray = HexColor("#f8fafc")
        self.label_gray = HexColor("#64748b")
        self.border_gray = HexColor("#e2e8f0")
        self.dark_gray = HexColor("#334155")

    def generate_qr_code(self, data: str) -> Image.Image:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=2
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        return img

    def create_digital_signature(self, payload: Payload) -> str:
        cert_json = json.dumps(payload, sort_keys=True)
        cert_hash = hashlib.sha256(cert_json.encode()).digest()
        signature = self.private_key.sign(
            cert_hash,
            ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(signature).decode()

    def generate_certificate_pdf(self, certificate: GenerateRequest):
        payload = certificate.payload
        provided_signature = certificate.signature
        buffer = io.BytesIO()

        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        # Layout constants
        margin = 40
        content_width = width - 2 * margin
        current_y = height - 60

        # Header Section
        logo_size = 36
        logo_x = margin + 20
        c.setFillColor(self.accent_blue)
        c.roundRect(logo_x, current_y - logo_size, logo_size, logo_size, 6, stroke=0, fill=1)
        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(logo_x + logo_size/2, current_y - logo_size/2 - 5, "SW")

        company_x = logo_x + logo_size + 20
        c.setFillColor(self.primary_blue)
        c.setFont("Helvetica-Bold", 20)
        c.drawString(company_x, current_y - 12, "Secure Wipe")
        c.setFont("Helvetica", 11)
        c.setFillColor(self.label_gray)
        c.drawString(company_x, current_y - 28, "Empowering Data Privacy & Security")

        current_y -= 80

        # Header divider
        c.setStrokeColor(self.border_gray)
        c.setLineWidth(1)
        c.line(margin, current_y, width - margin, current_y)
        current_y -= 30

        # Certificate Title
        c.setFont("Helvetica-Bold", 18)
        c.setFillColor(self.primary_blue)
        c.drawCentredString(width/2, current_y, "DRIVE WIPING DIGITAL CERTIFICATE")
        current_y -= 25

        # Subtitle
        c.setFont("Helvetica", 10)
        c.setFillColor(self.dark_gray)
        c.drawCentredString(width/2, current_y,
            "This certifies that the below-listed storage device has been securely erased")
        current_y -= 14
        c.drawCentredString(width/2, current_y,
            "in full compliance with NIST SP 800-88 Rev.1 and DoD 5220.22-M standards.")
        current_y -= 40

        details = [
            ("Certificate ID", payload.certificate_id or "N/A"),
            ("Drive Serial Number", payload.device.id or "N/A"),
            ("Wiping Standard", payload.wipe.policy or "N/A"),
            ("Wiping Algorithm", payload.wipe.method or "N/A"),
            ("Wiping Date & Time", payload.wipe.completed_at.isoformat() if payload.wipe.completed_at else "N/A"),
            ("Drive Model", payload.device.model or "N/A"),
            ("User ID", payload.user_id or "N/A"),
            ("Username", payload.username or "N/A"),
            ("Audit Reference ID", f"{payload.issuer.org} ({payload.issuer.signing_key_id})" if payload.issuer else "N/A"),
        ]

        # Table dimensions
        table_x = margin + 20
        table_width = content_width - 40
        row_height = 25
        table_height = len(details) * row_height + 10

        # Table background
        c.setFillColor(self.soft_gray)
        c.roundRect(table_x, current_y - table_height, table_width, table_height, 6, stroke=0, fill=1)

        # Table border
        c.setStrokeColor(self.border_gray)
        c.setLineWidth(1)
        c.roundRect(table_x, current_y - table_height, table_width, table_height, 6, stroke=1, fill=0)

        # Draw table rows
        label_width = table_width * 0.35
        value_x = table_x + label_width + 20

        for i, (label, value) in enumerate(details):
            row_y = current_y - (i * row_height) - 20

            if i > 0:
                c.setStrokeColor(self.border_gray)
                c.setLineWidth(0.5)
                c.line(table_x + 10, row_y + row_height - 5, table_x + table_width - 10, row_y + row_height - 5)

            c.setFont("Helvetica-Bold", 10)
            c.setFillColor(self.dark_gray)
            c.drawString(table_x + 15, row_y, label)

            c.setFont("Helvetica", 10)
            c.setFillColor(black)
            display_value = str(value)
            if len(display_value) > 45:
                display_value = display_value[:42] + "..."
            c.drawString(value_x, row_y, display_value)

        current_y -= table_height + 30

        # Bottom Section: Signature and QR Code
        bottom_section_height = 120

        # Digital signature box
        sig_width = content_width * 0.65
        sig_height = bottom_section_height
        sig_x = margin + 10
        sig_y = current_y - sig_height

        c.setFillColor(white)
        c.roundRect(sig_x, sig_y, sig_width, sig_height, 8, stroke=0, fill=1)
        c.setStrokeColor(self.border_gray)
        c.setLineWidth(1)
        c.roundRect(sig_x, sig_y, sig_width, sig_height, 8, stroke=1, fill=0)

        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(self.primary_blue)
        c.drawString(sig_x + 15, sig_y + sig_height - 20, "Digital Signature")

        c.setFont("Helvetica", 9)
        c.setFillColor(self.label_gray)
        c.drawString(sig_x + 15, sig_y + sig_height - 35, "Signed By: SecureWipe Signing Authority")

        issued_on = datetime.utcnow().strftime("%d-%b-%Y %H:%M:%S UTC")
        c.setFont("Helvetica", 9)
        c.setFillColor(self.dark_gray)
        c.drawString(sig_x + 15, sig_y + sig_height - 50, f"Issued On: {issued_on}")

        signature_text = provided_signature or self.create_digital_signature(payload)
        fingerprint = hashlib.sha256(signature_text.encode()).hexdigest()

        fp_box_x = sig_x + 10
        fp_box_y = sig_y + 10
        fp_box_w = sig_width - 20
        fp_box_h = 40

        c.setStrokeColor(self.border_gray)
        c.setFillColor(self.soft_gray)
        c.roundRect(fp_box_x, fp_box_y, fp_box_w, fp_box_h, 5, stroke=1, fill=1)

        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(self.primary_blue)
        c.drawString(fp_box_x + 8, fp_box_y + fp_box_h - 14, "SHA256 Fingerprint:")

        c.setFont("Courier", 7)
        c.setFillColor(self.dark_gray)
        c.drawString(fp_box_x + 8, fp_box_y + fp_box_h - 26, fingerprint[:64])
        c.drawString(fp_box_x + 8, fp_box_y + fp_box_h - 36, fingerprint[64:])

        # QR Code
        qr_size = 90
        qr_x = width - margin - qr_size - 10
        qr_y = sig_y + (sig_height - qr_size) / 2

        qr_data = f"https://verify.securewipe.com/cert/{payload.certificate_id or 'unknown'}"
        qr_img = self.generate_qr_code(qr_data)

        qr_buffer = io.BytesIO()
        qr_img.save(qr_buffer, format="PNG")
        qr_buffer.seek(0)
        qr_reader = ImageReader(qr_buffer)

        c.drawImage(qr_reader, qr_x, qr_y, width=qr_size, height=qr_size, mask='auto')

        c.setFont("Helvetica", 8)
        c.setFillColor(self.label_gray)
        c.drawCentredString(qr_x + qr_size/2, qr_y - 12, "Scan to Verify")

        footer_y = 40
        c.setFont("Helvetica", 8)
        c.setFillColor(self.dark_gray)
        c.drawCentredString(width/2, footer_y,
            "This certificate is digitally signed and tamper-proof. Verification can be performed using our SecureWipe Portal.")

        c.setFont("Helvetica", 7)
        c.setFillColor(self.label_gray)
        c.drawCentredString(width/2, footer_y - 15,
            "© 2025 SecureWipe. All Rights Reserved.")

        c.setStrokeColor(self.primary_blue)
        c.setLineWidth(2)
        c.roundRect(20, 20, width - 40, height - 40, 15, stroke=1, fill=0)

        c.showPage()
        c.save()

        buffer.seek(0)
        return buffer.read()
