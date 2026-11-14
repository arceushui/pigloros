# Read-only CI diagnostics only; never used to select a process or drive a fixture.
param([Parameter(Mandatory = $true)][string] $StopMarker)
$ErrorActionPreference = 'Stop'
$deadline = [DateTime]::UtcNow.AddMinutes(44)
$previous = $null
$lastEmission = [DateTime]::MinValue
$emissions = 0

function Emit-LocationState {
    try {
        $service = Get-Service -Name 'lfsvc' -ErrorAction Stop
        Write-Output "NATIVE_DESKTOP location_service=$($service.Status)"
    } catch { Write-Output 'NATIVE_DESKTOP location_service=unknown' }
    $flags = @(
        @{ Label = 'machine_disable_location'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Name = 'DisableLocation' },
        @{ Label = 'machine_disable_provider'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Name = 'DisableWindowsLocationProvider' },
        @{ Label = 'machine_disable_sensors'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Name = 'DisableSensors' },
        @{ Label = 'machine_location_consent'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'; Name = 'Value' },
        @{ Label = 'user_location_consent'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'; Name = 'Value' }
    )
    foreach ($flag in $flags) {
        try {
            $entry = Get-ItemProperty -LiteralPath $flag.Path -Name $flag.Name -ErrorAction Stop
            $raw = $entry.($flag.Name)
            $value = if ($raw -in @(0, 1, 'Allow', 'Deny')) { "$raw" } else { 'unknown' }
            Write-Output "NATIVE_DESKTOP $($flag.Label)=$value"
        } catch { Write-Output "NATIVE_DESKTOP $($flag.Label)=unknown" }
    }
}

Write-Output "NATIVE_DESKTOP start=$([DateTime]::UtcNow.ToString('o'))"
Emit-LocationState
while ($emissions -lt 128 -and [DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $StopMarker)) {
    $now = [DateTime]::UtcNow
    try {
        $windows = @()
        $incomplete = $false
        foreach ($process in @(Get-Process -ErrorAction Stop)) {
            try {
                $handle = $process.MainWindowHandle.ToInt64()
                if ($handle -ne 0) {
                    $name = [string]$process.ProcessName
                    if ($name -notmatch '^[A-Za-z0-9_.-]{1,80}$') { $name = 'unknown' }
                    $windows += [pscustomobject]@{ Id = $process.Id; Name = $name; Session = $process.SessionId; Handle = $handle }
                }
            } catch { $incomplete = $true }
        }
        $windows = @($windows | Sort-Object Id)
        $summary = ($windows | ForEach-Object { '{0}:{1}:{2}:{3:x}' -f $_.Id, $_.Name, $_.Session, $_.Handle }) -join ','
        if ($emissions -lt 128 -and ($summary -cne $previous -or ($now - $lastEmission).TotalSeconds -ge 60)) {
            $count = $windows.Count
            Write-Output "NATIVE_DESKTOP time=$($now.ToString('o')) count=$count incomplete=$incomplete shown_max=32 main_window_only=true"
            foreach ($item in @($windows | Select-Object -First 32)) {
                Write-Output ('NATIVE_DESKTOP_WINDOW pid={0} name={1} session={2} hwnd=0x{3:x}' -f $item.Id, $item.Name, $item.Session, $item.Handle)
            }
            $emissions++
            $lastEmission = $now
        }
        $previous = $summary
    } catch {
        if ($emissions -lt 128) { Write-Output "NATIVE_DESKTOP time=$($now.ToString('o')) snapshot=unknown"; $emissions++ }
    }
    Start-Sleep -Seconds 2
}
Write-Output "NATIVE_DESKTOP finished emissions=$emissions limit=128 main_window_absence=unknown"
