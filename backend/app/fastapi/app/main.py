from fastapi import FastAPI
from app.routers.auth_test import router as auth_test_router
app = FastAPI()

@app.get("/health")
async def health():
    return {"detail": {"status": "ok"}}

app.include_router(auth_test_router)