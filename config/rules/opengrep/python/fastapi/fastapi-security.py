from fastapi import FastAPI, Depends
import requests
import httpx

app = FastAPI()

# ruleid: python.fastapi.security.ssrf-user-url
@app.get("/fetch")
async def fetch_url(url: str):
    response = requests.get(url)
    return {"content": response.text}

# ok: python.fastapi.security.ssrf-user-url
@app.get("/health")
async def health_check():
    response = requests.get("https://api.internal.example.com/health")
    return {"status": response.status_code}
