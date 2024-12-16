from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
import httpx
import os
from binascii import hexlify

from utils.helpers import   (get_tls_public_key, 
                             get_tls_certificate,
                             convert_certificate_to_pem,
                            pem_string_to_bytes, 
                            pdf_sign, pdf_verify, 
                            pdf_verify_with_domain, 
                            extract_signatures_and_public_keys
                            
                            )

from utils.getpdfsignatures import(get_pdf_signatures,
                                   raw_ec_public_key_to_pem
                            
                            )
# Initialize the FastAPI application
app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/trustlists", StaticFiles(directory="trustlists"), name="trustlists")
templates = Jinja2Templates(directory="templates")

# Define a request model for URL input
class PDFUploadRequest(BaseModel):
    url: HttpUrl

# Directory to save uploaded PDFs
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Define a root endpoint
@app.get("/",response_class=HTMLResponse)
def read_root(request: Request):
    print(request.headers,  )
    return templates.TemplateResponse( "welcome.html", {"request": request, "title": "Welcome Page", "message": "Welcome to our TrustRoot Application!"})

@app.get("/get-public-key/")
async def get_public_key(domain: str ):
    hex_pubkey = "Not known"
    try:
        pubkey_from_url = get_tls_public_key(domain)
        hex_pubkey = hexlify(pem_string_to_bytes(pubkey_from_url.decode()))
    except:
        hex_pubkey = "could not retrieve"

    return {"domain": domain, "publickey": hex_pubkey}

@app.post("/submit")
async def submit_pdf(pdf_url:str = Form(...)):

    pdf_url = pdf_url.replace("https://github.com","https://raw.githubusercontent.com").replace("/blob","")

    try:
        # Download the PDF
        async with httpx.AsyncClient() as client:
            response = await client.get(pdf_url)
            response.raise_for_status()

        # Check if the content type indicates a PDF
        content_type = response.headers.get("Content-Type", "").lower()


        # Save the PDF to the local directory
        filename = os.path.join(UPLOAD_DIR, os.path.basename(pdf_url))
        with open(filename, "wb") as f:
            f.write(response.content)

        #return {"message": "PDF successfully uploaded", "filename": filename}

    except httpx.HTTPError as e:
        raise HTTPException(status_code=400, detail=f"Failed to download PDF: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
    
    pem = "ca/root/docsign.pem"
    print(filename,pem)
    try:
        all_sigok, all_hashok = pdf_verify(filename,pem)
    except Exception as e:
        
        return

    return {"detail": pdf_url, "sigok": all_sigok, "hashok": all_hashok}


@app.post("/verify-pdf/")
async def upload_pdf(file: UploadFile = File(...),
                     verifier: str = Form(...)):
    msg_out ="Verify:"
    # Check if the uploaded file is a PDF
    if file.content_type != "application/pdf":
        return JSONResponse(status_code=400, content={"message": "File must be a PDF."})

    # Save the uploaded file to a specific directory
    file_location = f"uploads/{file.filename}"
    with open(file_location, "wb") as f:
        f.write(await file.read())
    
    try:
        msg_out = pdf_verify(file_location,'ca/root/docsign.pem',verifier)
        for signature in get_pdf_signatures(file_location):
            certificate = signature.certificate
            raw_key_bytes = certificate.subject_public_key_info.public_key
            pem_key = raw_ec_public_key_to_pem(raw_key_bytes)
            msg_out += f"\nSigning Public Key from Document \n\n {pem_key}"
            
            pubkey_from_url = get_tls_public_key(verifier).decode()
            msg_out +=f"\nSigning Public Key from Website: {verifier} \n\n {pubkey_from_url}"
            hex_pubkey = hexlify(pem_string_to_bytes(pubkey_from_url))
            if pem_key==pubkey_from_url:
                msg_out +=f"VERIFIED!!! This document is signed by {verifier}. \nThis document CAN BE TRUSTED as being verified by: {verifier}!!! \n"
            else:
                msg_out+=f"ADVISORY!!! The signed document is NOT verified by {verifier}! \nWhile this document has been digitally signed and not altered, this document SHOULD NOT BE TRUSTED as being verified by {verifier}!!!\n"
    except:
        msg_out = "Could not verify"


    return {"message": f"{msg_out} {file.filename} at: {verifier}"}

@app.post("/upload-pdf-from-url/")
async def upload_pdf_from_url(request: PDFUploadRequest):
    """
    Downloads a PDF from the given URL, validates it, and saves it locally.

    Args:
        request (PDFUploadRequest): A request object containing the URL of the PDF.

    Returns:
        dict: A response indicating success or failure.
    """
    pdf_url = str(request.url)  # Convert HttpUrl to a string

    replace_url = pdf_url.replace("https://github.com","https://raw.githubusercontent.com").replace("/blob","")
    # print(replace_url)
    try:
        # Download the PDF
        async with httpx.AsyncClient() as client:
            response = await client.get(pdf_url)
            response.raise_for_status()

        # Check if the content type indicates a PDF
        content_type = response.headers.get("Content-Type", "").lower()


        # Save the PDF to the local directory
        filename = os.path.join(UPLOAD_DIR, os.path.basename(pdf_url))
        with open(filename, "wb") as f:
            f.write(response.content)

        return {"message": "PDF successfully uploaded", "filename": filename}

    except httpx.HTTPError as e:
        raise HTTPException(status_code=400, detail=f"Failed to download PDF: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")