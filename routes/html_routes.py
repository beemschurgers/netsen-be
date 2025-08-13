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

@router.get("/test-dashboard")
def test_dashboard():
    with open("templates/websocket_test_dashboard.html", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@router.get("/test/top-talkers")
def test_top_talkers():
    with open("templates/top_talkers_test.html", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@router.get("/test/devices")
def test_devices():
    with open("templates/devices_test.html", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@router.get("/test/network-stats")
def test_network_stats():
    with open("templates/network_stats_test.html", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@router.get("/test/system-performance")
def test_system_performance():
    with open("templates/system_performance_test.html", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@router.get("/test/threats")
def test_threats():
    with open("templates/threats_test.html", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@router.get("/enhanced-traffic-monitor")
def enhanced_traffic_monitor():
    with open("templates/enhanced_traffic_monitor.html", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)
