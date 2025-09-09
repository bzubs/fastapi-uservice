from fastapi import FastAPI, HTTPException, UploadFile, Depends, File
from fastapi.responses import JSONResponse, StreamingResponse
import json, uuid
from .config import CERT_DIR
from .wipe import wipe_folder, log_hash
from .signing import sign_payload, verify_payload
from .pdfgen import CertificateGenerator
from .pdfsign import sign_pdf, verify_pdf_signed_by_our_key
from .schemas import WipeRequest, DriveHealthInput, GenerateRequest
from .predict import predict_drive_health
from .code import get_features
from .security import require_internal_api_key
import io
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="SecureWipe Service")

certgen = CertificateGenerator()


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
                "method": req.method,
                "policy": req.policy,
                "started_at": rec["wipe"]["start_time"],
                "completed_at": rec["wipe"]["end_time"],
                "result": rec["final_result"],
                "log_hash": log_hash(rec),
            },
            "issuer": {"org": "SecureWipe", "signing_key_id": "ecdsa-p256-001"},
        }

        # Sign certificate JSON
        signed = sign_payload(cert_payload)

        signed = GenerateRequest(**signed)

        # Save JSON certificate
        cert_file = CERT_DIR / f"{cert_id}.json"
        cert_file.write_text(signed.model_dump_json(indent=2)) 

        # Return paths; GET endpoint for PDF still points to signed PDF
        return {
            "job_id": cert_id,
            "status": "completed",
            "certificate_json": signed.dict(),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/certificates/{cert_id}")
def get_certificate(cert_id: str):
    cert_file = CERT_DIR / f"{cert_id}.json"
    if not cert_file.exists():
        raise HTTPException(404, detail="Certificate not found")
    return JSONResponse(content=json.loads(cert_file.read_text()))


@app.post("/api/genpdf", dependencies=[Depends(require_internal_api_key)])
def generate_pdf(req: GenerateRequest):
    try:
        pdf_bytes = certgen.generate_certificate_pdf(req)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

        # Sign PDF and save in signed PDF directory
    pdf_buffer = io.BytesIO(pdf_bytes)
    try:
        signed_buffer = sign_pdf(pdf_buffer)
        signed_buffer.seek(0)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF signing failed: {e}")
    
    return StreamingResponse(
        signed_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={req.payload.certificate_id}_signed.pdf"}
    )


#deprecated endpoint, use new /genpdf endpoint
'''@app.get("/api/certificates/{cert_id}/pdf")
def get_certificate_pdf(cert_id: str):
    pdf_file = PDF_SIGNED_DIR / f"{cert_id}_signed.pdf"
    if not pdf_file.exists():
        raise HTTPException(404, detail="Signed PDF not found")
    return FileResponse(
        str(pdf_file),
        media_type="application/pdf",
        filename=f"{cert_id}_signed.pdf",
    )'''

#json verification end-point
@app.post("/api/verify-cert")
def verify_certificate(cert: dict):
    return {"valid": verify_payload(cert)}


@app.post("/api/verify-pdf")
async def verify_pdf_upload(file: UploadFile = File(...)):
    b = await file.read()
    res = await verify_pdf_signed_by_our_key(b)
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