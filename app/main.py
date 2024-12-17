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
                            extract_signatures_and_public_keys,
                            is_valid_domain
                            
                            )

from utils.getpdfsignatures import(get_pdf_signatures,
                                   raw_ec_public_key_to_pem,
                                   get_pem_public_key_from_certificate
                            
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

    out_msg = ""
    domain = ""
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
        try:
            for signature in get_pdf_signatures(filename):
                certificate = signature.certificate
                # parse_certificate(certificate=certificate)
                certificate_common_name = certificate.issuer.common_name
                if is_valid_domain(certificate_common_name):
                    print("THIS IS A VALID DOMAIN NAME")
                else:
                    print("NOT A VALID DOMAIN")

                domain = certificate_common_name
                # click.echo(f"certificate issuer common name: {certificate_common_name}")
                public_key_pem = get_pem_public_key_from_certificate(certificate)
                # click.echo(f"pem data: {public_key_pem}")

                # click.echo(f"\nSigning Public Key from Document: \n\n {public_key_pem}")
                pubkey_from_url = get_tls_public_key(domain).decode()
                # click.echo(f"\nSigning Public Key from Website: {domain} \n\n {pubkey_from_url}")
                hex_pubkey = hexlify(pem_string_to_bytes(pubkey_from_url))
                if public_key_pem==pubkey_from_url:
                    pass
                    out_msg = f"VERIFIED!!! This document is signed by {domain}.This document CAN BE TRUSTED as being verified by: {domain}!!!"
                else:
                    out_msg =f"ADVISORY!!! The signed document is NOT verified by {domain}! While this document has been digitally signed and not altered, this document SHOULD NOT BE TRUSTED as being verified by {domain}!!!"
        except Exception as e:
            print(f"{e}")



    except Exception as e:
        
        return

    return {"detail": pdf_url, "sigok": all_sigok, "hashok": all_hashok, "domain": domain, "out_msg": out_msg}


@app.post("/upload/")
async def upload_pdf(file: UploadFile = File(...)):
    
    out_msg =""
    domain = ""
    verifier = 'verify.openproof.org'
    # Check if the uploaded file is a PDF
    if file.content_type != "application/pdf":
        return JSONResponse(status_code=400, content={"message": "File must be a PDF."})

    # Save the uploaded file to a specific directory
    filename = f"uploads/{file.filename}"
    with open(filename, "wb") as f:
        f.write(await file.read())
    
    pem = "ca/root/docsign.pem"
    print(filename,pem)
    try:
        all_sigok, all_hashok = pdf_verify(filename,pem)
        try:
            for signature in get_pdf_signatures(filename):
                certificate = signature.certificate
                # parse_certificate(certificate=certificate)
                certificate_common_name = certificate.issuer.common_name
                if is_valid_domain(certificate_common_name):
                    print("THIS IS A VALID DOMAIN NAME")
                else:
                    print("NOT A VALID DOMAIN")

                domain = certificate_common_name
                # click.echo(f"certificate issuer common name: {certificate_common_name}")
                public_key_pem = get_pem_public_key_from_certificate(certificate)
                # click.echo(f"pem data: {public_key_pem}")

                # click.echo(f"\nSigning Public Key from Document: \n\n {public_key_pem}")
                pubkey_from_url = get_tls_public_key(domain).decode()
                # click.echo(f"\nSigning Public Key from Website: {domain} \n\n {pubkey_from_url}")
                hex_pubkey = hexlify(pem_string_to_bytes(pubkey_from_url))
                if public_key_pem==pubkey_from_url:
                    pass
                    out_msg = f"VERIFIED!!! This document is signed by {domain}.This document CAN BE TRUSTED as being verified by: {domain}!!!"
                else:
                    out_msg =f"ADVISORY!!! The signed document is NOT verified by {domain}! While this document has been digitally signed and not altered, this document SHOULD NOT BE TRUSTED as being verified by {domain}!!!"
        except Exception as e:
            print(f"{e}")



    except Exception as e:
        
        return


    return {"detail": filename, "sigok": all_sigok, "hashok": all_hashok, "domain": domain, "out_msg": out_msg}

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