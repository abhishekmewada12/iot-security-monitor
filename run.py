import sys
import os
import uvicorn

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")

    print("=" * 65)
    print("  🛡️  SHIELD-IoT // Intrusion Detection & Threat Mitigation")
    print("=" * 65)
    print(f"  ► Server starting at: http://{host}:{port}")
    print(f"  ► Real-time WebSocket: ws://{host}:{port}/ws")
    print("  ► Press Ctrl+C to terminate.")
    print("=" * 65)

    uvicorn.run("backend.main:app", host=host, port=port, log_level="info")
