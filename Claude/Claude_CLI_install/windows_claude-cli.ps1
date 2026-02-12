 [CmdletBinding()]
param(
    [switch]$UserMode,
    [string]$ConfigFile = "",
    [bool]$EnablePrompt = $false,
    [string]$AnthropicApiKey = "",
    [string]$Model = "claude-sonnet-4-20250514",
    [int]$MaxTokens = 700,
    [bool]$ForceReinstall = $true,
    [bool]$SkipInstall = $false,
    [string]$ClaudeInstallScriptUrl = "https://claude.ai/install.ps1",
    [string]$ClaudeNpmPackage = "@anthropic-ai/claude-code"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

<#
Script Name: Claude Code Setup (Windows, Intune-safe)
Purpose:
  - Install / reinstall Claude Code
  - Optionally prompt for API key/model/max tokens
  - Persist config to user profile and user environment variables
  - Handle SYSTEM context by switching work to active user session
#>

$LogRoot = Join-Path $env:ProgramData "Temp\Logs"
$LogPath = Join-Path $LogRoot "claudeapi-bootstrap.log"
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

function Write-Log {
    param([Parameter(Mandatory = $true)][string]$Message)
    $line = "[claudeapi] $Message"
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
    param([string]$UserProfilePath)

    $candidates = @(
        (Join-Path $UserProfilePath ".local\bin\claude.cmd"),
        (Join-Path $UserProfilePath ".local\bin\claude.exe"),
        (Join-Path $UserProfilePath ".local\bin\claude"),
        (Join-Path $UserProfilePath "AppData\Local\Programs\Claude\claude.exe"),
        (Join-Path $UserProfilePath "AppData\Local\Programs\Claude Code\claude.exe")
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

function Remove-LegacyClaudeFunction {
    $profilePaths = @(
        $PROFILE.CurrentUserAllHosts,
        $PROFILE.CurrentUserCurrentHost
    ) | Select-Object -Unique

    foreach ($profilePath in $profilePaths) {
        if ([string]::IsNullOrWhiteSpace($profilePath)) { continue }
        if (-not (Test-Path -LiteralPath $profilePath)) { continue }

        $content = Get-Content -LiteralPath $profilePath -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($content)) { continue }

        $updated = [Regex]::Replace($content, '(?ms)^\s*function\s+claude\b[^{]*\{.*?^\s*}\s*', "")
        if ($updated -ne $content) {
            Write-Log "Removing legacy 'function claude' from profile: $profilePath"
            Set-Content -LiteralPath $profilePath -Value $updated -Encoding UTF8
        }
    }
}

function Install-ClaudeCode {
    param([Parameter(Mandatory = $true)][string]$UserProfilePath)

    $installed = $false

    try {
        Write-Log "Installing Claude Code via official installer script"
        $scriptText = Invoke-RestMethod -Uri $ClaudeInstallScriptUrl -Method Get
        Invoke-Expression $scriptText
        $installed = $true
    } catch {
        Write-Log "Official install script failed: $($_.Exception.Message)"
    }

    if (-not $installed) {
        $npm = Get-Command -Name "npm" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $npm -and -not [string]::IsNullOrWhiteSpace($npm.Path)) {
            Write-Log "Falling back to npm install: $ClaudeNpmPackage"
            & $npm.Path install -g $ClaudeNpmPackage
            if ($LASTEXITCODE -eq 0) {
                $installed = $true
            } else {
                Write-Log "npm install failed with exit code $LASTEXITCODE"
            }
        } else {
            Write-Log "npm not found; skipping npm fallback"
        }
    }

    if (-not $installed) {
        throw "Claude Code install failed. Validate installer URL, internet access, and npm availability."
    }

    $claudePath = Get-ClaudePath -UserProfilePath $UserProfilePath
    if ([string]::IsNullOrWhiteSpace($claudePath)) {
        throw "Claude Code install completed but 'claude' binary was not found."
    }

    return $claudePath
}

function Validate-ApiSettings {
    param(
        [Parameter(Mandatory = $true)][string]$ApiKeyValue,
        [Parameter(Mandatory = $true)][string]$ModelValue,
        [Parameter(Mandatory = $true)][int]$MaxTokenValue
    )

    if ([string]::IsNullOrWhiteSpace($ApiKeyValue)) {
        throw "Empty API key."
    }
    if ([string]::IsNullOrWhiteSpace($ModelValue)) {
        throw "Empty model."
    }
    if ($MaxTokenValue -le 0) {
        throw "Invalid max tokens value: $MaxTokenValue"
    }

    $headers = @{
        "x-api-key" = $ApiKeyValue
        "anthropic-version" = "2023-06-01"
    }

    try {
        $response = Invoke-WebRequest -Uri "https://api.anthropic.com/v1/models" -Method Get -Headers $headers
        if ($response.StatusCode -ne 200) {
            throw "Expected HTTP 200 but got $($response.StatusCode)"
        }
    } catch {
        throw "API key validation failed: $($_.Exception.Message)"
    }
}

function Persist-ClaudeConfig {
    param(
        [Parameter(Mandatory = $true)][string]$UserProfilePath,
        [Parameter(Mandatory = $true)][string]$ApiKeyValue,
        [Parameter(Mandatory = $true)][string]$ModelValue,
        [Parameter(Mandatory = $true)][int]$MaxTokenValue
    )

    $configDir = Join-Path $UserProfilePath ".config\claude"
    $envFile = Join-Path $configDir "env.ps1"

    New-Item -ItemType Directory -Path $configDir -Force | Out-Null

    $fileBody = @(
        ('$env:ANTHROPIC_API_KEY = "{0}"' -f ($ApiKeyValue -replace '"', '\"'))
        ('$env:ANTHROPIC_MODEL = "{0}"' -f ($ModelValue -replace '"', '\"'))
        ('$env:ANTHROPIC_MAX_TOKENS = "{0}"' -f $MaxTokenValue)
    ) -join "`r`n"

    Set-Content -LiteralPath $envFile -Value $fileBody -Encoding UTF8

    [Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", $ApiKeyValue, "User")
    [Environment]::SetEnvironmentVariable("ANTHROPIC_MODEL", $ModelValue, "User")
    [Environment]::SetEnvironmentVariable("ANTHROPIC_MAX_TOKENS", [string]$MaxTokenValue, "User")

    $env:ANTHROPIC_API_KEY = $ApiKeyValue
    $env:ANTHROPIC_MODEL = $ModelValue
    $env:ANTHROPIC_MAX_TOKENS = [string]$MaxTokenValue

    $profilePath = $PROFILE.CurrentUserAllHosts
    if (-not [string]::IsNullOrWhiteSpace($profilePath)) {
        $profileDir = Split-Path -Path $profilePath -Parent
        if (-not (Test-Path -LiteralPath $profileDir)) {
            New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        }

        if (-not (Test-Path -LiteralPath $profilePath)) {
            New-Item -ItemType File -Path $profilePath -Force | Out-Null
        }

        $sourceLine = ". `"$envFile`""
        $profileContent = Get-Content -LiteralPath $profilePath -Raw -ErrorAction SilentlyContinue
        if ($null -eq $profileContent -or $profileContent -notmatch [Regex]::Escape($sourceLine)) {
            Add-Content -LiteralPath $profilePath -Value $sourceLine -Encoding UTF8
        }
    }

    Write-Log "Config file written: $envFile"
}

function Invoke-InteractivePrompt {
    param(
        [string]$CurrentModel,
        [int]$CurrentMaxTokens
    )

    $modelPrompt = "Select model [claude-sonnet-4-20250514 | claude-opus-4-20250514 | claude-haiku-4-20250514] (default: $CurrentModel)"
    $selectedModel = Read-Host -Prompt $modelPrompt
    if ([string]::IsNullOrWhiteSpace($selectedModel)) {
        $selectedModel = $CurrentModel
    }

    $keyInput = Read-Host -Prompt "Enter Anthropic API key"
    $tokensInput = Read-Host -Prompt "Max tokens (default: $CurrentMaxTokens)"

    $selectedMaxTokens = $CurrentMaxTokens
    if (-not [string]::IsNullOrWhiteSpace($tokensInput)) {
        if ($tokensInput -notmatch '^\d+$') {
            throw "Invalid max tokens input: $tokensInput"
        }
        $selectedMaxTokens = [int]$tokensInput
    }

    return [PSCustomObject]@{
        ApiKey = $keyInput
        Model = $selectedModel
        MaxTokens = $selectedMaxTokens
    }
}

function Invoke-SetupForCurrentUser {
    $userProfilePath = [Environment]::GetFolderPath("UserProfile")
    if ([string]::IsNullOrWhiteSpace($userProfilePath)) {
        throw "Could not determine user profile path."
    }

    Remove-LegacyClaudeFunction

    if ($ForceReinstall) {
        $localBin = Join-Path $userProfilePath ".local\bin"
        $toRemove = @(
            (Join-Path $localBin "claude"),
            (Join-Path $localBin "claude.cmd"),
            (Join-Path $localBin "claude.exe")
        )
        foreach ($path in $toRemove) {
            if (Test-Path -LiteralPath $path) {
                Write-Log "Removing existing Claude binary stub: $path"
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $claudePath = Get-ClaudePath -UserProfilePath $userProfilePath
    if (-not $SkipInstall -or [string]::IsNullOrWhiteSpace($claudePath)) {
        $claudePath = Install-ClaudeCode -UserProfilePath $userProfilePath
    }

    if ([string]::IsNullOrWhiteSpace($claudePath)) {
        throw "Claude Code not detected after setup."
    }

    Write-Log "Using Claude binary: $claudePath"

    $apiKeyToUse = $AnthropicApiKey
    $modelToUse = $Model
    $maxTokensToUse = $MaxTokens

    if ($EnablePrompt -and [string]::IsNullOrWhiteSpace($apiKeyToUse)) {
        try {
            $promptResult = Invoke-InteractivePrompt -CurrentModel $modelToUse -CurrentMaxTokens $maxTokensToUse
            $apiKeyToUse = $promptResult.ApiKey
            $modelToUse = $promptResult.Model
            $maxTokensToUse = $promptResult.MaxTokens
        } catch {
            throw "Prompt failed. Provide non-interactive params instead. $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($apiKeyToUse)) {
        Write-Log "EnablePrompt=false and no API key provided; skipping API/model/token configuration."
        Write-Log "You can configure API settings later in user environment variables."
        return 0
    }

    Validate-ApiSettings -ApiKeyValue $apiKeyToUse -ModelValue $modelToUse -MaxTokenValue $maxTokensToUse
    Persist-ClaudeConfig -UserProfilePath $userProfilePath -ApiKeyValue $apiKeyToUse -ModelValue $modelToUse -MaxTokenValue $maxTokensToUse

    Write-Log "Claude Code installed and configuration persisted successfully."
    return 0
}

# Load staged config payload if provided (used for SYSTEM -> user handoff).
if (-not [string]::IsNullOrWhiteSpace($ConfigFile) -and (Test-Path -LiteralPath $ConfigFile)) {
    try {
        $cfg = Get-Content -LiteralPath $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -ne $cfg) {
            if ($null -ne $cfg.EnablePrompt) { $EnablePrompt = [bool]$cfg.EnablePrompt }
            if ($null -ne $cfg.AnthropicApiKey) { $AnthropicApiKey = [string]$cfg.AnthropicApiKey }
            if ($null -ne $cfg.Model) { $Model = [string]$cfg.Model }
            if ($null -ne $cfg.MaxTokens) { $MaxTokens = [int]$cfg.MaxTokens }
            if ($null -ne $cfg.ForceReinstall) { $ForceReinstall = [bool]$cfg.ForceReinstall }
            if ($null -ne $cfg.SkipInstall) { $SkipInstall = [bool]$cfg.SkipInstall }
            if ($null -ne $cfg.ClaudeInstallScriptUrl) { $ClaudeInstallScriptUrl = [string]$cfg.ClaudeInstallScriptUrl }
            if ($null -ne $cfg.ClaudeNpmPackage) { $ClaudeNpmPackage = [string]$cfg.ClaudeNpmPackage }
        }
    } finally {
        Remove-Item -LiteralPath $ConfigFile -Force -ErrorAction SilentlyContinue
    }
}

if ($UserMode.IsPresent) {
    exit (Invoke-SetupForCurrentUser)
}

if (-not (Get-IsSystemContext)) {
    exit (Invoke-SetupForCurrentUser)
}

Write-Log "Running as SYSTEM; switching to active user session for user-scoped setup."
$activeUser = Get-ActiveUser
if ($null -eq $activeUser) {
    Write-Log "No active interactive user found; skipping setup (Intune-safe no-op)."
    exit 0
}

$scriptRoot = Join-Path $env:ProgramData "Temp\Scripts"
New-Item -ItemType Directory -Path $scriptRoot -Force | Out-Null
$stagedScript = Join-Path $scriptRoot "claudeapi.ps1"
$stagedConfig = Join-Path $scriptRoot ("claudeapi-config-{0}.json" -f ([DateTime]::UtcNow.ToString("yyyyMMddHHmmss")))
Copy-Item -LiteralPath $PSCommandPath -Destination $stagedScript -Force

$payload = @{
    EnablePrompt = $EnablePrompt
    AnthropicApiKey = $AnthropicApiKey
    Model = $Model
    MaxTokens = $MaxTokens
    ForceReinstall = $ForceReinstall
    SkipInstall = $SkipInstall
    ClaudeInstallScriptUrl = $ClaudeInstallScriptUrl
    ClaudeNpmPackage = $ClaudeNpmPackage
}
$payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $stagedConfig -Encoding UTF8

$taskName = "Saronic-ClaudeApi-{0}" -f ([DateTime]::UtcNow.ToString("yyyyMMddHHmmss"))
$runTime = (Get-Date).AddMinutes(1)
$taskArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", ('"{0}"' -f $stagedScript),
    "-UserMode",
    "-ConfigFile", ('"{0}"' -f $stagedConfig)
)

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($taskArgs -join " ")
$trigger = New-ScheduledTaskTrigger -Once -At $runTime
$principal = New-ScheduledTaskPrincipal -UserId $activeUser.Sid -LogonType InteractiveToken -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 20)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Log "Started user-context task '$taskName' for $($activeUser.UserName)."
Start-Sleep -Seconds 8

try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
} catch {
    Write-Log "Cleanup warning: could not remove task '$taskName' immediately."
}

Write-Log "SYSTEM phase complete."
exit 0
