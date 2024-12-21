from fastapi import Request, APIRouter, Depends, Response, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse
from pydantic import BaseModel
import random
import string
from app.models import REDIR_PREFIX

class URLRequest(BaseModel):
    long_url: str

url_mapping = {}

def generate_short_code(length: int = 12) -> str:
    """Generate a simple random short code of given length."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

router = APIRouter()

@router.post("/shorten")
async def shorten(request: Request, url_to_shorten: URLRequest):

    long_url = url_to_shorten.long_url.strip()
    if not long_url:
        raise HTTPException(status_code=400, detail="Invalid URL")

    # Generate a unique short code that doesn't collide
    while True:
        short_code = generate_short_code()
        if short_code not in url_mapping:
            break
    
    url_mapping[short_code] = long_url

    # Here we assume your FastAPI app is running at "http://localhost:8000"
    short_url = f"http://localhost:8000{REDIR_PREFIX}/{short_code}"
    return {"short_url": short_url, "long_url": long_url}

@router.get("/{short_code}")
def redirect_to_long(short_code: str):
    if short_code not in url_mapping:
        raise HTTPException(status_code=404, detail="Short URL not found")
    long_url = url_mapping[short_code]
    print(long_url)
    return RedirectResponse(url=long_url, status_code=307)
   