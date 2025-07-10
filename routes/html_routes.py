from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

@router.get("/")
def get():
    html_content = open("templates/index.html").read()
    return HTMLResponse(content=html_content)

@router.get("/threat-detection")
def threat_detection():
    with open("templates/threat_detection.html", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)