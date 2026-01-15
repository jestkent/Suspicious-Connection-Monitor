# Suspicious Connection Monitor (Beginner Cybersecurity Project)

This project is a beginner-friendly **endpoint visibility and network monitoring tool** built using Windows PowerShell.

It helps answer a very important cybersecurity question:

“What processes on my computer are communicating on the network right now?”

This tool is **defensive only**. It does not block traffic, terminate processes, or modify system settings. It only reads and reports information already available on the system.

---

## What this program does

The Suspicious Connection Monitor performs the following actions:

1. Collects all current TCP network connections on the system
2. Identifies which process (application) owns each connection using the PID
3. Displays connection details such as:
   - Local address and port
   - Remote address and port
   - Connection state
   - Process name and path when available
4. Applies simple beginner-friendly detection rules
5. Flags connections that may be worth investigating
6. Saves a CSV report for documentation and review

---

## Why this is useful in cybersecurity

In real-world blue team and SOC work, analysts often need to:

- Identify unknown outbound connections
- Spot processes listening for inbound connections
- Investigate unusual ports
- Map network activity back to running processes
- Quickly triage suspicious behavior

This project practices those exact skills in a safe and controlled way.

---

## Detection flags explained

The script assigns flags to help you focus your investigation.  
Flags are **not proof of malicious activity**. They are signals for review.

### CHECK_PORT
The remote port is in a small list of ports that are commonly abused or unusual.

Examples include:
- 4444
- 1337
- 6667
- 31337
- 8081
- 9001

These ports are often used in demos, reverse shells, or custom services.

---

### LISTENING
The process is in a listening state and waiting for inbound connections.

This can be normal for system services or development tools, but listening ports are always worth reviewing because attackers often open listening backdoors.

---

### PUBLIC_REMOTE
The remote IP address is not local or private.

This means the process is communicating with a public internet address.  
This is normal for browsers and cloud apps, but suspicious for unknown or unexpected processes.

---

## Project structure

Suspicious-Connection-Monitor/
├─ README.md
├─ scripts/
│ └─ net-watch.ps1
└─ output/
└─ net-report_YYYY-MM-DD_HH-mm-ss.csv

yaml
Copy code

Each run creates a new CSV report in the `output` folder.

---

## Requirements

- Windows 10 or Windows 11
- PowerShell
- Administrator access is recommended for better process visibility

---

## How to run the program

### Step 1: Open PowerShell
For best results:
- Right-click PowerShell
- Select “Run as administrator”

---

### Step 2: Navigate to the repository folder

Example:
```powershell
D:
cd D:\Desktop\Suspicious-Connection-Monitor
Step 3: Allow script execution for this session only
powershell
Copy code
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Type Y if prompted.

This change only applies to the current PowerShell window and resets when it is closed.

Step 4: Run the script
powershell
Copy code
.\scripts\net-watch.ps1
What happens when you run it
A table of active connections is printed to the screen

Flagged connections appear first for easier review

A CSV report is saved in the output folder

A summary shows total connections and how many were flagged

How to read the output
Each row represents one network connection.

Important columns:

Process
The name of the application owning the connection

PID
Process ID. This is used to investigate further

ProcessPath
Where the executable is running from. Malware often runs from unusual locations

State
Examples include Established, Listen, TimeWait

Local
Your local IP address and port

Remote
The remote IP address and port

Flags
Reasons the connection was flagged for review

Quick investigation steps for any PID
When you see a PID that looks interesting, investigate it further.

Step 1: Identify the process
Pick one PID you want to understand, then run:

powershell
Copy code
Get-Process -Id 9160 | Select-Object Id, ProcessName, Path
This tells you:

The process name

The executable path

Whether the location makes sense

Step 2: Get deeper process details if needed
If the path is missing or unclear:

powershell
Copy code
Get-CimInstance Win32_Process -Filter "ProcessId=9160" | Select-Object Name, ExecutablePath, CommandLine
This can reveal:

Full executable location

Command-line arguments

Suspicious launch behavior

Step 3: Ask analyst-style questions
Is this a program I expect to be running?

Does the port match the application’s purpose?

Is the executable path normal?

Does this process have many connections?

Is it listening for inbound traffic?

Example investigation summary
Finding:
A process was detected communicating with a public IP address on an uncommon port.

Evidence:
The Suspicious Connection Monitor flagged the connection using the CHECK_PORT and PUBLIC_REMOTE rules.

Assessment:
Further investigation of the PID showed the process path and behavior were consistent with a known application.

Conclusion:
The activity was determined to be expected and not malicious.

Limitations
This is a learning-focused project with intentional simplicity.

Limitations include:

No real-time monitoring

No automatic blocking

No reputation lookups

Simple heuristic-based flags

Possible improvements
Future enhancements could include:

Allowlist for known safe processes

Noise reduction for common ports like 443

Top processes by connection count

Scheduled execution

JSON output for SIEM ingestion