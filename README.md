# Shell-Command-Interpreter
# 🔐 Remote Command Execution and File Transfer Shell (Windows)

This project implements a **remote command execution shell with file transfer capabilities** over TCP sockets using the **Windows Sockets API (Winsock)**. It allows you to host a server that listens for incoming connections, or connect to a server and interact with the remote system using built-in commands.

---

## 🚀 Features

- ✅ Remote shell access with command execution  
- 📥 File upload (client ➜ server)  
- 📤 File download (server ➜ client)  
- 🎨 Fun commands: `rickroll`, `matrix`, `disco`, `troll`  
- 🧠 Built-in shell with prompt customization  
- 🔄 Server listens for clients (one-at-a-time model)  
- ⚙️ Windows-only (uses WinAPI and `cmd.exe`)  
- 🧱 Minimal dependencies, clean ANSI C code  

---

## ⚙️ Prerequisites

- Windows OS  
- Visual Studio or MinGW compiler  
- Winsock2 support  

---

## 🛠️ How to Compile

### Using Visual Studio (Developer Command Prompt)

```bash
cl shell.c /Fe:shell.exe /link ws2_32.lib
