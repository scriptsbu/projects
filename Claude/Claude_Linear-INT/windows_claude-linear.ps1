[CmdletBinding()]
param(
    [switch]$UserMode,
    [string]$McpServerName = "linear-server",
    [string]$McpUrl = "https://mcp.linear.app/mcp",
    [switch]$LaunchClaudeAfterSetup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

<#
Script Name: Claude Linear MCP Setup (Windows / Intune-safe)

Behavior:
  - Idempotently registers Linear MCP in Claude user scope.
  - Works when launched as user or as SYSTEM (Intune).
  - If run as SYSTEM, it schedules a short-lived task in the active user's
    session to execute the user-scoped Claude MCP commands.

Notes:
  - This script intentionally avoids interactive prompts.
  - OAuth is completed by the user in Claude after setup.
#>

$LogRoot = Join-Path $env:ProgramData "Saronic\Logs"
$LogPath = Join-Path $LogRoot "linear-claude-bootstrap.log"
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

function Write-Log {
    param([Parameter(Mandatory = $true)][string]$Message)
    $line = "[linear-claude] $Message"
    Write-Host $line
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function Get-IsSystemContext {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return ($sid -eq "S-1-5-18")
}

function Get-ActiveUser {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($null -eq $cs -or [string]::IsNullOrWhiteSpace($cs.UserName)) {
        return $null
    }

    $ntAccount = New-Object System.Security.Principal.NTAccount($cs.UserName)
    $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $profilePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath

    return [PSCustomObject]@{
        UserName = $cs.UserName
        Sid = $sid
        ProfilePath = $profilePath
    }
}

function Get-ClaudePath {
    $profilePath = [Environment]::GetFolderPath("UserProfile")
    $candidates = @(
        (Join-Path $profilePath ".local\bin\claude.cmd"),
        (Join-Path $profilePath ".local\bin\claude.exe"),
        (Join-Path $profilePath ".local\bin\claude"),
        (Join-Path $profilePath "AppData\Local\Programs\Claude\claude.exe"),
        (Join-Path $profilePath "AppData\Local\Programs\Claude Code\claude.exe")
    )

    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) {
            return $path
        }
    }

    $cmd = Get-Command -Name "claude" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Path)) {
        return $cmd.Path
    }

    return $null
}

function Invoke-LinearMcpSetupForCurrentUser {
    $claudePath = Get-ClaudePath
    if ([string]::IsNullOrWhiteSpace($claudePath)) {
        Write-Log "Claude not found for current user; skipping Linear MCP setup"
        return 0
    }

    Write-Log "Using Claude binary: $claudePath"

    $listOutput = & $claudePath "mcp" "list" 2>&1
    if ($LASTEXITCODE -eq 0 -and ($listOutput -join "`n") -match [Regex]::Escape($McpServerName)) {
        Write-Log "Linear MCP already configured; nothing to do"
        return 0
    }

    Write-Log "Registering MCP server '$McpServerName' ($McpUrl)"
    & $claudePath "mcp" "add" "-s" "user" "--transport" "http" $McpServerName $McpUrl
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to register Linear MCP server in Claude."
    }

    if ($LaunchClaudeAfterSetup.IsPresent) {
        Write-Log "Launching Claude for user to complete OAuth"
        Start-Process -FilePath $claudePath | Out-Null
    }

    Write-Log "Linear MCP setup complete. User should open Claude and run /mcp to complete OAuth."
    return 0
}

if ($UserMode.IsPresent) {
    exit (Invoke-LinearMcpSetupForCurrentUser)
}

if (-not (Get-IsSystemContext)) {
    exit (Invoke-LinearMcpSetupForCurrentUser)
}

Write-Log "Running as SYSTEM context; switching to active user session via scheduled task"
$activeUser = Get-ActiveUser
if ($null -eq $activeUser) {
    Write-Log "No active interactive user found; skipping setup (Intune-safe no-op)"
    exit 0
}

$scriptRoot = Join-Path $env:ProgramData "Saronic\Scripts"
New-Item -ItemType Directory -Path $scriptRoot -Force | Out-Null
$stagedScript = Join-Path $scriptRoot "linear-claude.ps1"
Copy-Item -LiteralPath $PSCommandPath -Destination $stagedScript -Force

$taskName = "Saronic-LinearClaudeMcp-{0}" -f ([DateTime]::UtcNow.ToString("yyyyMMddHHmmss"))
$runTime = (Get-Date).AddMinutes(1)
$taskArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", ('"{0}"' -f $stagedScript),
    "-UserMode",
    "-McpServerName", ('"{0}"' -f $McpServerName),
    "-McpUrl", ('"{0}"' -f $McpUrl)
)
if ($LaunchClaudeAfterSetup.IsPresent) {
    $taskArgs += "-LaunchClaudeAfterSetup"
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($taskArgs -join " ")
$trigger = New-ScheduledTaskTrigger -Once -At $runTime
$principal = New-ScheduledTaskPrincipal -UserId $activeUser.Sid -LogonType InteractiveToken -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Log "Started user-context task '$taskName' for $($activeUser.UserName)"
Start-Sleep -Seconds 8

try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
} catch {
    Write-Log "Cleanup warning: could not remove task '$taskName' immediately"
}

Write-Log "SYSTEM phase complete"
exit 0
