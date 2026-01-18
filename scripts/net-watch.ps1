<#
Suspicious Connection Monitor (Beginner Friendly)
My Personal Cybersecurity Scripts
Author: Jestkent and AI

What this script does:
- Reads current network connections on your Windows machine
- Shows which process (app) owns each connection
- Flags connections that may be worth investigating

What this script does NOT do:
- It does NOT block traffic
- It does NOT modify firewall rules
- It does NOT kill processes
- It does NOT scan the internet
- It only reports what it sees

Why this is useful in cybersecurity:
- Malware often opens outbound connections (beaconing)
- Remote tools and backdoors may use unusual ports
- A quick visibility tool helps you spot “what is my machine talking to right now?”
#>

# -----------------------------
# 1) Beginner "suspicious ports" list
# -----------------------------
# These ports are not always malicious.
# We flag them because they are commonly used in:
# - reverse shells demos
# - botnet command channels (historically)
# - IRC related traffic (older, still seen sometimes)
# - unusual proxies or dev tunnels
#
# You can edit this list later as you learn.
$suspiciousPorts = @(4444, 1337, 6667, 31337, 5555, 9001, 8081, 2222)

# -----------------------------
# 2) Create output folder for reports
# -----------------------------
# We save reports to /output so you can attach them as evidence in GitHub.
$outDir = Join-Path $PSScriptRoot "..\output"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Create a timestamp so each report is unique
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outFileCsv = Join-Path $outDir "net-report_$timestamp.csv"

# -----------------------------
# 3) Collect TCP connections
# -----------------------------
# Get-NetTCPConnection is built into Windows (PowerShell).
# We include multiple states because security investigations may care about:
# - Established: actively connected
# - Listen: waiting for incoming connections (important for backdoors)
# - TimeWait/CloseWait: normal but sometimes noisy
#
# If you want a smaller output, you can filter only Established.
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue

# -----------------------------
# 4) Helper function to get process info from a PID
# -----------------------------
function Get-ProcessInfo {
    param([int]$Pid)

    # Some PIDs may disappear quickly (process closes).
    # Some system processes require admin to read details.
    try {
        $p = Get-Process -Id $Pid -ErrorAction Stop

        # Path is useful: malware often runs from weird folders (Temp, AppData, etc.)
        # Path may be blank for some system processes.
        $path = ""
        try { $path = $p.Path } catch { $path = "" }

        return @{
            Name = $p.ProcessName
            Path = $path
        }
    } catch {
        return @{
            Name = "Unknown"
            Path = ""
        }
    }
}

# -----------------------------
# 5) Convert raw connections into a clean investigation table
# -----------------------------
# We build a list of objects with:
# - process name, pid, path
# - local address, remote address
# - state
# - flags (why it might be suspicious)
$report = foreach ($c in $connections) {

    # Skip entries that do not have a local port (rare but can happen)
    if (-not $c.LocalPort) { continue }

    $proc = Get-ProcessInfo -Pid $c.OwningProcess

    # Build readable endpoints like "192.168.1.10:52344"
    $localEndpoint = "$($c.LocalAddress):$($c.LocalPort)"
    $remoteEndpoint = "$($c.RemoteAddress):$($c.RemotePort)"

    # -----------------------------
    # Flag logic (simple and beginner-friendly)
    # -----------------------------
    # Flag 1: suspicious port
    $flagPort = $false
    if ($suspiciousPorts -contains $c.RemotePort) { $flagPort = $true }

    # Flag 2: listening state (a process is waiting for inbound connections)
    # This can be normal (browser, system services), but also important to review.
    $flagListen = $false
    if ($c.State -eq "Listen") { $flagListen = $true }

    # Flag 3: remote address is public vs local
    # Local ranges:
    # - 127.0.0.1 / ::1 (localhost)
    # - 10.x.x.x, 172.16-31.x.x, 192.168.x.x (private)
    # This is a basic heuristic, not perfect.
    $flagPublic = $false
    $ra = $c.RemoteAddress.ToString()

    $isLocalhost = ($ra -eq "127.0.0.1" -or $ra -eq "::1")
    $isPrivateV4 = ($ra -like "10.*" -or $ra -like "192.168.*" -or $ra -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.")
    $isBlankRemote = ([string]::IsNullOrWhiteSpace($ra) -or $ra -eq "0.0.0.0" -or $ra -eq "::")

    # For established connections, a public remote IP can be normal (websites),
    # but if the process looks suspicious, this flag helps you focus.
    if (-not $isLocalhost -and -not $isPrivateV4 -and -not $isBlankRemote) {
        $flagPublic = $true
    }

    # Combine flags into a readable reason
    $reasons = @()
    if ($flagPort)   { $reasons += "CHECK_PORT" }
    if ($flagListen) { $reasons += "LISTENING" }
    if ($flagPublic) { $reasons += "PUBLIC_REMOTE" }

    [PSCustomObject]@{
        Process      = $proc.Name
        PID          = $c.OwningProcess
        ProcessPath  = $proc.Path
        State        = $c.State
        Local        = $localEndpoint
        Remote       = $remoteEndpoint
        Flags        = ($reasons -join ",")
    }
}

# -----------------------------
# 6) Show results on screen
# -----------------------------
Write-Host ""
Write-Host "=== Suspicious Connection Monitor ==="
Write-Host "Flags:"
Write-Host "  CHECK_PORT    = remote port is in suspicious list (not always malicious)"
Write-Host "  LISTENING     = process is waiting for inbound connections"
Write-Host "  PUBLIC_REMOTE = remote address is not local/private"
Write-Host ""

# Show flagged items first so you can focus quickly
$report |
    Sort-Object @{Expression="Flags"; Descending=$true}, Process |
    Format-Table -AutoSize

# -----------------------------
# 7) Export report to CSV for evidence
# -----------------------------
$report | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outFileCsv

Write-Host ""
Write-Host "Report saved to: $outFileCsv"

# -----------------------------
# 8) Quick summary counts (useful for README screenshots)
# -----------------------------
$flagged = $report | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Flags) }

Write-Host ""
Write-Host "Total connections found: $($report.Count)"
Write-Host "Flagged connections:     $($flagged.Count)"

# If there are flagged entries, show a short list for quick review
if ($flagged.Count -gt 0) {
    Write-Host ""
    Write-Host "Top flagged items (first 10):"
    $flagged |
        Select-Object -First 10 Process, PID, State, Remote, Flags |
        Format-Table -AutoSize
}
