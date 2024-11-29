from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse

# Initialize the FastAPI application
app = FastAPI()

# Define a root endpoint
@app.get("/")
def read_root():
    return {"message": "Welcome to Sigbot!"}


@app.post("/upload-pdf/")
async def upload_pdf(file: UploadFile = File(...)):
    # Check if the uploaded file is a PDF
    if file.content_type != "application/pdf":
        return JSONResponse(status_code=400, content={"message": "File must be a PDF."})

    # Save the uploaded file to a specific directory
    file_location = f"uploads/{file.filename}"
    with open(file_location, "wb") as f:
        f.write(await file.read())
    
    return {"message": f"Successfully uploaded {file.filename}"}