from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
import json, uuid
from pathlib import Path
from .config import CERT_DIR
from .wipe import wipe_folder, log_hash
from .signing import sign_payload, verify_payload
from .pdfgen import CertificateGenerator
from .pdfsign import sign_pdf_with_pyhanko, verify_pdf_signed_by_our_key
from .schemas import WipeRequest, DriveHealthInput
from .predict import predict_drive_health
from .code import get_features


app = FastAPI(title="SecureWipe Service")

certgen = CertificateGenerator('keys/private_key.pem')


# PDF directories
PDF_UNSIGNED_DIR = CERT_DIR / "uspdf"   # unsigned PDFs
PDF_SIGNED_DIR = CERT_DIR / "spdf"      # signed PDFs
PDF_UNSIGNED_DIR.mkdir(parents=True, exist_ok=True)
PDF_SIGNED_DIR.mkdir(parents=True, exist_ok=True)


@app.post("/api/wipe")
def start_wipe(req: WipeRequest):
    try:
        # Wipe folder
        rec = wipe_folder(req.dev_path)
        if rec.get("final_result") != "PASS":
            raise HTTPException(status_code=500, detail="Wipe failed")

        # Certificate payload
        cert_id = str(uuid.uuid4())
        cert_payload = {
            "certificate_id": cert_id,
            "user_id": req.user_id,
            "username": req.username,
            "device": req.device.dict(),
            "wipe": {
                "method": rec["wipe"]["method"],
                "policy": "NIST SP 800-88",
                "started_at": rec["wipe"]["start_time"],
                "completed_at": rec["wipe"]["end_time"],
                "result": rec["final_result"],
                "log_hash": log_hash(rec),
            },
            "issuer": {"org": "SecureWipe", "signing_key_id": "ecdsa-p256-001"},
        }

        # Sign certificate JSON
        signed = sign_payload(cert_payload)

        # Save JSON certificate
        cert_file = CERT_DIR / f"{cert_id}.json"
        cert_file.write_text(json.dumps(signed))

        # Generate unsigned PDF
        pdf_unsigned_out = PDF_UNSIGNED_DIR / f"{cert_id}.pdf"
        try:
            certgen.generate_certificate_pdf(signed, pdf_unsigned_out)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

        # Sign PDF and save in signed PDF directory
        pdf_signed_out = PDF_SIGNED_DIR / f"{cert_id}_signed.pdf"
        try:
            sign_pdf_with_pyhanko(str(pdf_unsigned_out), str(pdf_signed_out))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF signing failed: {e}")

        if not pdf_signed_out.exists():
            raise HTTPException(status_code=500, detail="Signed PDF not found after signing")

        # Return paths; GET endpoint for PDF still points to signed PDF
        return {
            "job_id": cert_id,
            "status": "completed",
            "certificate_json": signed,
            "certificate_pdf": str(pdf_signed_out),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/certificates/{cert_id}")
def get_certificate(cert_id: str):
    cert_file = CERT_DIR / f"{cert_id}.json"
    if not cert_file.exists():
        raise HTTPException(404, detail="Certificate not found")
    return JSONResponse(content=json.loads(cert_file.read_text()))


@app.get("/api/certificates/{cert_id}/pdf")
def get_certificate_pdf(cert_id: str):
    pdf_file = PDF_SIGNED_DIR / f"{cert_id}_signed.pdf"
    if not pdf_file.exists():
        raise HTTPException(404, detail="Signed PDF not found")
    return FileResponse(
        str(pdf_file),
        media_type="application/pdf",
        filename=f"{cert_id}_signed.pdf",
    )


@app.post("/api/verify-cert")
def verify_certificate(cert: dict):
    return {"valid": verify_payload(cert)}


@app.post("/api/verify-pdf")
async def verify_pdf_upload(file: UploadFile = File(...)):
    b = await file.read()
    signer_cert_pem = "keys/certificate.pem"
    res = await verify_pdf_signed_by_our_key(b, signer_cert_pem)
    return JSONResponse(content=res)

@app.post("/api/drive/health")
def drive_health(payload: DriveHealthInput):
    """
    Predict drive health based on SMART and other features.
    Input: JSON list of 142 features (optional for testing)
    Output: probability score between 0 (bad) and 1 (good)
    """

    if payload.drive_id == '555':
        features = get_features()
    else:
        raise HTTPException(status_code=400, detail="Expected a valid Drive ID")
        

    try:
        prob, health_class = predict_drive_health(features)
        return {"health_score": prob, "health_class": health_class}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")