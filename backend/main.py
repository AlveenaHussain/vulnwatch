from fastapi import FastAPI

app = FastAPI(title="VulnWatch API")


@app.get("/health")
def health_check():
    return {"status": "healthy"}