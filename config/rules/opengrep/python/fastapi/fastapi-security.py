from fastapi import FastAPI, Depends
import requests
import httpx

app = FastAPI()

@app.get("/fetch")
async def fetch_url(url: str):
    # ruleid: python.fastapi.security.ssrf-user-url
    response = requests.get(url)
    return {"content": response.text}

@app.get("/health")
async def health_check():
    # ok: python.fastapi.security.ssrf-user-url
    response = requests.get("https://api.internal.example.com/health")
    return {"status": response.status_code}
