from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

@router.get("/")
def get():
    html_content = open("templates/index.html").read()
    return HTMLResponse(content=html_content)