<#
.SYNOPSIS
    Removes legacy admin account and logs to Azure Log Analytics (Runs only once)
.DESCRIPTION
    This script removes a specified legacy admin account after performing safety checks
    and logs all actions to Azure Log Analytics for centralized monitoring.
    Includes run-once logic using registry marker.
.NOTES
    Deploy via Intune as a PowerShell script
    Author: IT Admin
    Date: 2026-02-06
#>

#region Configuration
$legacyAdmin = "OldAdmin"  # CHANGE THIS to your legacy admin username
$workspaceId = "12345678-1234-1234-1234-123456789012"  # CHANGE THIS to your Log Analytics Workspace ID
$workspaceKey = "your-workspace-key-here=="  # CHANGE THIS to your Log Analytics Workspace Key
$logType = "LegacyAdminRemoval"  # Custom log table name (will appear as LegacyAdminRemoval_CL in Log Analytics)
$removeProfile = $false  # Set to $true if you want to remove the user profile as well

# Run-once registry marker
$registryPath = "HKLM:\SOFTWARE\IT\Scripts"
$registryName = "LegacyAdminRemovalCompleted"
#endregion

#region Functions
Function Send-LogAnalyticsData {
    <#
    .SYNOPSIS
        Sends data to Azure Log Analytics
    #>
    param (
        [string]$WorkspaceId,
        [string]$WorkspaceKey,
        [string]$LogType,
        [object]$LogData
    )
    
    try {
        # Convert log data to JSON
        $json = $LogData | ConvertTo-Json -Depth 10
        $body = [System.Text.Encoding]::UTF8.GetBytes($json)

        # Create authorization signature
        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $body.Length
        
        $xHeaders = "x-ms-date:" + $rfc1123date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
        
        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($WorkspaceKey)
        
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $authorization = 'SharedKey {0}:{1}' -f $WorkspaceId, $encodedHash

        # Create URI
        $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

        # Create headers
        $headers = @{
            "Authorization"        = $authorization
            "Log-Type"            = $LogType
            "x-ms-date"           = $rfc1123date
            "time-generated-field" = "Timestamp"
        }

        # Send request
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
        
        return $response.StatusCode
    }
    catch {
        Write-Error "Failed to send data to Log Analytics: $_"
        return $null
    }
}

Function Get-RemainingAdmins {
    <#
    .SYNOPSIS
        Gets list of remaining local administrator accounts
    #>
    try {
        $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction Stop
        $members = Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop
        $adminList = $members | Where-Object { $_.ObjectClass -eq "User" } | Select-Object -ExpandProperty Name
        return ($adminList -join ", ")
    }
    catch {
        return "Unable to retrieve admin list"
    }
}

Function Test-UserLoggedIn {
    <#
    .SYNOPSIS
        Checks if a specific user is currently logged in
    #>
    param([string]$Username)
    
    try {
        $loggedInUsers = quser 2>&1
        if ($loggedInUsers -match $Username) {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

Function Set-ScriptCompleted {
    <#
    .SYNOPSIS
        Sets registry marker to indicate script has completed
    #>
    param(
        [string]$Path,
        [string]$Name,
        [string]$Status
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        $value = @{
            Status = $Status
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            DeviceName = $env:COMPUTERNAME
        } | ConvertTo-Json -Compress
        
        Set-ItemProperty -Path $Path -Name $Name -Value $value -Force
        Write-Host "✓ Registry marker set successfully" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not set registry marker: $_"
    }
}
#endregion

#region Main Script
Write-Host "========================================"
Write-Host "Legacy Admin Account Removal Script"
Write-Host "Device: $env:COMPUTERNAME"
Write-Host "Target Account: $legacyAdmin"
Write-Host "========================================"

# Check if script has already run successfully
Write-Host "`nChecking if script has already been executed..."
if (Test-Path $registryPath) {
    $existingValue = Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue
    if ($existingValue) {
        $markerData = $existingValue.$registryName | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($markerData.Status -eq "Success" -or $markerData.Status -eq "NotFound") {
            Write-Host "Script has already run successfully on $($markerData.Timestamp)" -ForegroundColor Yellow
            Write-Host "Status: $($markerData.Status)" -ForegroundColor Yellow
            Write-Host "Exiting without changes." -ForegroundColor Yellow
            Exit 0
        }
    }
}
Write-Host "✓ First run detected. Proceeding..." -ForegroundColor Green

# Initialize log data
$logData = [PSCustomObject]@{
    DeviceName = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    UsernameRemoved = $legacyAdmin
    Status = "Unknown"
    RemainingAdmins = ""
    ErrorDetails = ""
    ProfileRemoved = $false
}

try {
    # Check if legacy admin exists
    Write-Host "`nChecking if legacy admin account exists..."
    $user = Get-LocalUser -Name $legacyAdmin -ErrorAction SilentlyContinue
    
    if (-not $user) {
        Write-Host "Legacy admin account '$legacyAdmin' not found. Nothing to remove." -ForegroundColor Yellow
        $logData.Status = "NotFound"
        $logData.ErrorDetails = "Account does not exist on this device"
        $logData.RemainingAdmins = Get-RemainingAdmins
        
        # Send to Log Analytics
        $statusCode = Send-LogAnalyticsData -WorkspaceId $workspaceId -WorkspaceKey $workspaceKey -LogType $logType -LogData $logData
        if ($statusCode -eq 200) {
            Write-Host "Log sent to Azure Log Analytics successfully." -ForegroundColor Green
        }
        
        # Set registry marker
        Set-ScriptCompleted -Path $registryPath -Name $registryName -Status "NotFound"
        
        Exit 0
    }

    Write-Host "Legacy admin account '$legacyAdmin' found." -ForegroundColor Cyan

    # Safety Check 1: Check if user is logged in
    Write-Host "`nPerforming safety checks..."
    if (Test-UserLoggedIn -Username $legacyAdmin) {
        Write-Host "ERROR: User '$legacyAdmin' is currently logged in. Cannot remove." -ForegroundColor Red
        $logData.Status = "Failed"
        $logData.ErrorDetails = "User is currently logged in"
        $logData.RemainingAdmins = Get-RemainingAdmins
        
        # Send to Log Analytics
        Send-LogAnalyticsData -WorkspaceId $workspaceId -WorkspaceKey $workspaceKey -LogType $logType -LogData $logData
        
        # Don't set registry marker - allow retry later
        Exit 1
    }
    Write-Host "✓ User is not currently logged in" -ForegroundColor Green

    # Safety Check 2: Ensure at least one other admin exists
    $adminGroup = Get-LocalGroup -Name "Administrators"
    $admins = Get-LocalGroupMember -Group $adminGroup | Where-Object { $_.ObjectClass -eq "User" }
    
    if ($admins.Count -le 1) {
        Write-Host "ERROR: Cannot remove the only local administrator account." -ForegroundColor Red
        $logData.Status = "Failed"
        $logData.ErrorDetails = "Cannot remove the only local administrator"
        $logData.RemainingAdmins = Get-RemainingAdmins
        
        # Send to Log Analytics
        Send-LogAnalyticsData -WorkspaceId $workspaceId -WorkspaceKey $workspaceKey -LogType $logType -LogData $logData
        
        # Don't set registry marker - allow retry later
        Exit 1
    }
    Write-Host "✓ Other administrator accounts exist ($($admins.Count) total admins)" -ForegroundColor Green

    # Remove the local user account
    Write-Host "`nRemoving legacy admin account '$legacyAdmin'..."
    Remove-LocalUser -Name $legacyAdmin -ErrorAction Stop
    Write-Host "✓ Successfully removed account '$legacyAdmin'" -ForegroundColor Green
    
    $logData.Status = "Success"
    
    # Remove user profile if specified
    if ($removeProfile) {
        Write-Host "`nAttempting to remove user profile..."
        try {
            $profile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -like "*\$legacyAdmin" }
            if ($profile) {
                $profile | Remove-CimInstance -ErrorAction Stop
                Write-Host "✓ Successfully removed user profile" -ForegroundColor Green
                $logData.ProfileRemoved = $true
            } else {
                Write-Host "Profile not found for user '$legacyAdmin'" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "Warning: Could not remove profile: $_" -ForegroundColor Yellow
            $logData.ErrorDetails = "Account removed but profile removal failed: $_"
        }
    }
    
    # Get remaining admins
    $logData.RemainingAdmins = Get-RemainingAdmins
    Write-Host "`nRemaining administrator accounts: $($logData.RemainingAdmins)" -ForegroundColor Cyan

    # Set registry marker for successful completion
    Set-ScriptCompleted -Path $registryPath -Name $registryName -Status "Success"

}
catch {
    Write-Host "`nERROR: Failed to remove legacy admin account" -ForegroundColor Red
    Write-Host "Error details: $_" -ForegroundColor Red
    
    $logData.Status = "Failed"
    $logData.ErrorDetails = $_.Exception.Message
    $logData.RemainingAdmins = Get-RemainingAdmins
    
    # Send to Log Analytics
    Send-LogAnalyticsData -WorkspaceId $workspaceId -WorkspaceKey $workspaceKey -LogType $logType -LogData $logData
    
    # Don't set registry marker on failure - allow retry
    Exit 1
}

# Send success log to Log Analytics
Write-Host "`nSending log data to Azure Log Analytics..."
$statusCode = Send-LogAnalyticsData -WorkspaceId $workspaceId -WorkspaceKey $workspaceKey -LogType $logType -LogData $logData

if ($statusCode -eq 200) {
    Write-Host "✓ Log sent to Azure Log Analytics successfully." -ForegroundColor Green
} else {
    Write-Host "Warning: Failed to send log to Azure Log Analytics" -ForegroundColor Yellow
}

Write-Host "`n========================================"
Write-Host "Script completed successfully"
Write-Host "========================================"

Exit 0
#endregion