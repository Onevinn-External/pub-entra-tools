#Requires -Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns, pwpush
<#
.SYNOPSIS
Creates 2 break-glass accounts with TAPs and adds them to a privileged group while excluding from MFA policies.

.DESCRIPTION
This script:
1. Creates 2 break-glass accounts with random names
2. Sets GUID-based passwords and disables password change on next logon
3. Generates Temporary Access Passes (TAPs) for each account
4. Pushes TAPs using pwpush module
5. Creates "psg-ice" privileged group and adds both users
6. Excludes the group from MFA-enforcing Conditional Access Policies
#>

param(
    [string]$TenantId,
    [switch]$Interactive
)

# Connect to Microsoft Graph
if ($Interactive) {
    Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess" -TenantId $TenantId
}

function New-RandomAccountName {
    <#
    .SYNOPSIS
    Generates a random name for break-glass accounts
    #>
    $adjectives = @("swift", "brave", "bold", "quick", "sharp", "strong", "smart", "wise")
    $nouns = @("eagle", "falcon", "tiger", "lion", "wolf", "bear", "hawk", "phoenix")
    
    $adjective = $adjectives | Get-Random
    $noun = $nouns | Get-Random
    $random = Get-Random -Minimum 100 -Maximum 999
    
    return "bg-$adjective-$noun-$random"
}

function New-BreakGlassAccount {
    <#
    .SYNOPSIS
    Creates a single break-glass account with specified parameters
    #>
    param(
        [string]$UserPrincipalNamePrefix
    )
    
    $displayName = "Break Glass - $(New-RandomAccountName)"
    $upn = "$UserPrincipalNamePrefix@$((Get-MgOrganization).VerifiedDomains[0].Name)"
    $password = [guid]::NewGuid().ToString()
    
    # Create user account
    $userParams = @{
        UserPrincipalName            = $upn
        DisplayName                  = $displayName
        MailNickname                 = $displayName.Replace(" ", "").ToLower()
        PasswordProfile              = @{
            ForceChangePasswordNextSignIn = $false
            Password                      = $password
        }
        AccountEnabled               = $true
    }
    
    $user = New-MgUser @userParams
    Write-Host "Created user: $upn" -ForegroundColor Green
    
    return @{
        User     = $user
        Password = $password
    }
}

function New-TemporaryAccessPass {
    <#
    .SYNOPSIS
    Creates a Temporary Access Pass (TAP) for a user
    #>
    param(
        [string]$UserId
    )
    
    $tapParams = @{
        isUsableOnce = $false
        lifetime     = 43200 # 30 days in minutes
    }
    
    $tap = New-MgUserAuthenticationTemporaryAccessPass -UserId $UserId -BodyParameter $tapParams
    
    return $tap.TemporaryAccessPass
}

function Invoke-PwPush {
    <#
    .SYNOPSIS
    Pushes TAP to pwpush and returns share link
    #>
    param(
        [string]$TapCode,
        [string]$AccountUpn
    )
    
    $pwpushPayload = @{
        password     = $TapCode
        payload_type = "note"
        note         = "TAP for $AccountUpn - Break Glass Account. Delete after use."
    }
    
    try {
        $response = Invoke-PwPush -Payload ($pwpushPayload | ConvertTo-Json) -ErrorAction Stop
        return $response.link
    }
    catch {
        Write-Warning "Failed to push TAP to pwpush: $_"
        return $TapCode
    }
}

function New-PrivilegedGroup {
    <#
    .SYNOPSIS
    Creates the break-glass privileged group
    #>
    param(
        [array]$MemberIds
    )
    
    $groupParams = @{
        DisplayName         = "psg-ice"
        Description         = "Privileged Break Glass Group - Infrastructure/Contingency/Emergency"
        MailEnabled         = $false
        SecurityEnabled     = $true
        MailNickname        = "psg-ice"
    }
    
    $group = New-MgGroup @groupParams
    Write-Host "Created group: psg-ice ($($group.Id))" -ForegroundColor Green
    
    # Add members
    foreach ($memberId in $MemberIds) {
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $memberId
    }
    
    return $group
}

function Update-ConditionalAccessPolicies {
    <#
    .SYNOPSIS
    Excludes psg-ice group from MFA-enforcing Conditional Access Policies
    #>
    param(
        [string]$GroupId
    )
    
    $policies = Get-MgIdentityConditionalAccessPolicy
    $mfaPolicies = $policies | Where-Object {
        $_.Conditions.ClientApplications.IncludeApplications -or 
        $_.GrantControls.BuiltInControls -contains "mfa" -or
        $_.GrantControls.BuiltInControls -contains "compliantDevice"
    }
    
    foreach ($policy in $mfaPolicies) {
        if ($policy.State -eq "enabled") {
            # Exclude group from policy
            if ($null -eq $policy.Conditions.Users.ExcludeGroups) {
                $policy.Conditions.Users.ExcludeGroups = @()
            }
            
            if ($GroupId -notin $policy.Conditions.Users.ExcludeGroups) {
                $policy.Conditions.Users.ExcludeGroups += $GroupId
                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $policy
                Write-Host "Updated policy: $($policy.DisplayName)" -ForegroundColor Green
            }
        }
    }
}

# Main execution
try {
    Write-Host "=== Break Glass Account Creation ===" -ForegroundColor Cyan
    
    # Create 2 break-glass accounts
    Write-Host "Creating break-glass accounts..." -ForegroundColor Yellow
    $account1 = New-BreakGlassAccount -UserPrincipalNamePrefix "bg-account-1"
    $account2 = New-BreakGlassAccount -UserPrincipalNamePrefix "bg-account-2"
    
    # Create TAPs
    Write-Host "Generating Temporary Access Passes..." -ForegroundColor Yellow
    $tap1 = New-TemporaryAccessPass -UserId $account1.User.Id
    $tap2 = New-TemporaryAccessPass -UserId $account2.User.Id
    
    # Push TAPs via pwpush
    Write-Host "Pushing TAPs to pwpush..." -ForegroundColor Yellow
    $tap1Link = Invoke-PwPush -TapCode $tap1 -AccountUpn $account1.User.UserPrincipalName
    $tap2Link = Invoke-PwPush -TapCode $tap2 -AccountUpn $account2.User.UserPrincipalName
    
    # Create privileged group
    Write-Host "Creating privileged group 'psg-ice'..." -ForegroundColor Yellow
    $group = New-PrivilegedGroup -MemberIds @($account1.User.Id, $account2.User.Id)
    
    # Update Conditional Access Policies
    Write-Host "Updating Conditional Access Policies..." -ForegroundColor Yellow
    Update-ConditionalAccessPolicies -GroupId $group.Id
    
    # Output summary
    Write-Host "`n=== Break Glass Setup Complete ===" -ForegroundColor Green
    Write-Host "Account 1: $($account1.User.UserPrincipalName)"
    Write-Host "  Password: $($account1.Password)"
    Write-Host "  TAP Link: $tap1Link"
    Write-Host ""
    Write-Host "Account 2: $($account2.User.UserPrincipalName)"
    Write-Host "  Password: $($account2.Password)"
    Write-Host "  TAP Link: $tap2Link"
    Write-Host ""
    Write-Host "Group: psg-ice ($($group.Id))"
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Share TAP links with end users securely"
    Write-Host "2. Users authenticate and register passkeys"
    Write-Host "3. Assign Global Administrator role to both accounts"
    Write-Host "4. Store passwords and TAPs in secure vault"
    
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
