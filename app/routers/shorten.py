from fastapi import Request, APIRouter, Depends, Response, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse
from pydantic import BaseModel
import random
import string
import redis
from app.models import REDIR_PREFIX, Settings

settings = Settings()

class URLRequest(BaseModel):
    long_url: str
    base_domain: str = "trustroot.ca"

url_mapping = {}
redis_server = redis.Redis(settings.REDIS_SERVER)

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
    redis_server.set(short_code,long_url)
    print(redis_server.get(short_code).decode())
    # url_mapping[short_code] = long_url

    # Here we assume your FastAPI app is running at "http://localhost:8000"
    request_base_url = str(request.base_url).replace("http","https")
    
    short_url = f"https://{url_to_shorten.base_domain}{REDIR_PREFIX}/{short_code}"
    return {"short_url": short_url, "long_url": long_url}

@router.get("/{short_code}")
def redirect_to_long(request: Request, short_code: str):
    # if short_code not in url_mapping:
    #    raise HTTPException(status_code=404, detail="Short URL not found")
    try:
        long_url = redis_server.get(short_code).decode()
        print(long_url)
        # long_url = url_mapping[short_code]
        return RedirectResponse(url=long_url, status_code=307)
    except:
        # long_url =f"/{REDIR_PREFIX}/whoops"
        raise HTTPException(status_code=404, detail="Short URL not found")
        
    
    return {"detail": "not found"}
   
@router.get("/whoops")
def get_whoops(request: Request):
    return {"detail": "whoops"}