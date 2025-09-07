import io
from pyhanko.sign.signers import SimpleSigner, PdfSignatureMetadata
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import ValidationContext
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
import os
from cryptography import x509 as crypto_x509
from pyhanko.sign.validation import validate_pdf_signature, async_validate_pdf_signature
from cryptography.hazmat.primitives import serialization
from asn1crypto import x509 as asn1_x509

from pyhanko.sign.validation import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader

KEY_PATH =  "keys/private_key.pem"
CERT_PATH = "keys/certificate.pem"


def ensure_cert_files():
    """Ensure PEM key/cert files exist locally (write from env if not)."""
    priv_data = os.getenv("PRIVATE_KEY_PEM")
    cert_data = os.getenv("CERTIFICATE_PEM")

    if priv_data and not KEY_PATH.exists():
        KEY_PATH.write_text(priv_data)
    if cert_data and not CERT_PATH.exists():
        CERT_PATH.write_text(cert_data)

    if not KEY_PATH.exists() or not CERT_PATH.exists():
        raise RuntimeError("Key or cert missing. Provide via env or local files.")

def load_simple_signer():
    return SimpleSigner.load(
        key_file=KEY_PATH,
        cert_file=CERT_PATH,
        ca_chain_files=None,
        key_passphrase=None,
    )

def sign_pdf_with_pyhanko(input_pdf_path: str, output_pdf_path: str):
    signer = load_simple_signer()
    with open(input_pdf_path, "rb") as f:
        data = f.read()
    writer = IncrementalPdfFileWriter(io.BytesIO(data))
    append_signature_field(writer, sig_field_spec=SigFieldSpec(sig_field_name="Signature1", box=(50,50,250,120)))
    meta = PdfSignatureMetadata(field_name="Signature1", reason="Wipe Certificate", location="SecureWipe")
    pdf_signer = signers.PdfSigner(meta, signer=signer)
    out = io.BytesIO()
    pdf_signer.sign_pdf(writer, output=out)
    with open(output_pdf_path, "wb") as f:
        f.write(out.getvalue())
# pdfsign.py


async def verify_pdf_signed_by_our_key(pdf_bytes: bytes, signer_cert_pem_path: str) -> dict:
  
    # load certificate
    with open(signer_cert_pem_path, "rb") as f:
        pem = f.read()
    crypto_cert = crypto_x509.load_pem_x509_certificate(pem)
    cert_der = crypto_cert.public_bytes(serialization.Encoding.DER)
    cert_obj = asn1_x509.Certificate.load(cert_der)
    vc = ValidationContext(trust_roots=[cert_obj])

    reader = PdfFileReader(io.BytesIO(pdf_bytes))
    if not reader.embedded_signatures:
        return {"valid": False, "reason": "no signatures"}
    sig = reader.embedded_signatures[0]
    v = await async_validate_pdf_signature(sig, vc)  # await here
    return {"valid": v.trusted, "coverage": str(v.coverage)}
