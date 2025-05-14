:: Start the FastAPI backend with admin privileges
powershell -Command "Start-Process cmd -ArgumentList '/k cd /d %CD% && uvicorn main:app --reload' -Verb RunAs"