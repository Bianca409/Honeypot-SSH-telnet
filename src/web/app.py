from fastapi import FastAPI

app = FastAPI(title="SSH/Telnet Honeypot Dashboard")


@app.get("/")
def home():
    return {"status": "ok", "message": "Honeypot Dashboard backend is running"}
