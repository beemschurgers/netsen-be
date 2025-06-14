from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.websocket_routes import router as ws_router
from routes.html_routes import router as html_router

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(html_router)
app.include_router(ws_router)