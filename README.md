# CHIMERA

**The Absolute Nightmare**

CHIMERA is a multi‑module offensive security and automation framework built for advanced penetration testing, research, and red‑team simulations. Designed with a hybrid of Python, Java, and custom modules, CHIMERA provides an all‑in‑one ecosystem for reconnaissance, exploitation, payload execution, data exfiltration, and automation.

> ⚠️ **Legal Notice:** CHIMERA is intended **only** for ethical hacking, research, and penetration testing on systems you *own* or have **written permission** to test.

---

## ⚡ Features

* **Multi‑Core Architecture**

  * `chimera_core.py`, `chimera_core2.py`, and `chimera_core3.py` work together to create layered functionality.
* **Automated Recon & Execution**

  * Custom routines for scanning, payload dispatching, and automation.
* **Data Exfiltration Module**

  * `chimera_exfil` handles controlled exfiltration tests.
* **Remote Execution Server**

  * `chimera_server.py` enables command execution pipelines.
* **Graphical Tools Included**

  * `MemeViewer` built with Kivy (Android‑packable) for image rendering.
* **Modular Expansion**

  * `/modules` folder allows plug‑and‑play module development.
* **Cross‑Platform**

  * Works on Linux, Termux, and Virtualized Kali.

---

## 📁 Directory Structure

```
CHIMERA/
│
├── chimera_core.py
├── chimera_core2.py
├── chimera_core3.py
├── chimera_server.py
├── chimera_exfil/
├── MemeViewer/
│   ├── main.py
│   ├── buildozer.spec
│   └── bin/
├── modules/
├── main.py
├── banner.py
├── build_chimera.sh
├── Execution_guide.txt
└── necessities.txt
```

---

## 🚀 Installation

### **Termux / Android**

```bash
git clone https://github.com/cvjthecyberwolf/CHIMERA.git
cd CHIMERA
python3 main.py
```

### **Linux / Kali**

```bash
git clone https://github.com/cvjthecyberwolf/CHIMERA.git
cd CHIMERA
python3 main.py
```

---

## 📱 Building MemeViewer as an APK

Inside the `MemeViewer` folder:

```bash
cd MemeViewer
buildozer -v android debug
```

APK will appear in:

```
MemeViewer/bin/
```

---

## 🧠 Usage

Run the main controller:

```bash
python3 main.py
```

Modules can be executed from the main interface or imported independently.

---

## 🛠 Requirements

* Python 3.10+
* Linux or Termux
* Optional: Android SDK + Buildozer (for APK builds)
* Packages listed in `necessities.txt`

---

## 📜 License

This project is licensed under the **GPL‑3.0 License**.

---

## 👤 Author

**CVJ The Cyber Wolf**
Advanced Cybersecurity Developer, Offensive Engineer, and Automation Architect.

---

## ⭐ Contribute

Pull requests are welcome! For major changes, please open an issue first.

If you like the project, give it a ⭐ on GitHub!

---

