#Requires -Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, KpPwpush
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
    Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "UserAuthenticationMethod.ReadWrite.All" -TenantId $TenantId
}

# KpPwpush must be initialized before New-KpPwpush can be used
Connect-KpPwpush | Out-Null

function New-RandomAccountName {
    <#
    .SYNOPSIS
    Generates a realistic first/last name so the account blends in as a regular person
    #>
    $firstNames = @("James", "Emma", "Liam", "Olivia", "Noah", "Ava", "William", "Sophia", "Lucas", "Isabella", "Henry", "Mia", "Oscar", "Amelia", "Leo", "Charlotte")
    $lastNames = @("Andersson", "Johansson", "Karlsson", "Nilsson", "Eriksson", "Larsson", "Olsson", "Persson", "Svensson", "Gustafsson", "Pettersson", "Jonsson")
    
    $firstName = $firstNames | Get-Random
    $lastName = $lastNames | Get-Random
    
    return [PSCustomObject]@{
        FirstName = $firstName
        LastName  = $lastName
    }
}

function New-BreakGlassAccount {
    <#
    .SYNOPSIS
    Creates a single break-glass account with a non-identifiable name
    #>
    # No parameters - name is fully randomized so the account isn't identifiable as break-glass
    $randomName = New-RandomAccountName
    $displayName = "$($randomName.FirstName) $($randomName.LastName)"
    # Trailing digit avoids UPN collisions between the two generated accounts, matching common corporate naming
    $mailNickname = "$($randomName.FirstName).$($randomName.LastName)$(Get-Random -Minimum 1 -Maximum 99)".ToLower()
    # Break-glass accounts must use the tenant root (*.onmicrosoft.com) domain - cloud-only, unaffected by federation/custom-domain outages
    $rootDomain = (Get-MgOrganization).VerifiedDomains | Where-Object { $_.IsInitial } | Select-Object -First 1
    $upn = "$mailNickname@$($rootDomain.Name)"
    $password = ConvertTo-SecureString ([guid]::NewGuid().ToString()) -AsPlainText -Force
    
    # Create user account
    $userParams = @{
        UserPrincipalName            = $upn
        DisplayName                  = $displayName
        MailNickname                 = $mailNickname
        PasswordProfile              = @{
            ForceChangePasswordNextSignIn = $false
            Password                      = [System.Net.NetworkCredential]::new('', $password).Password
        }
        AccountEnabled               = $true
    }
    
    $user = New-MgUser @userParams
    return @{
        User     = $user
        Password = $password
    }
}

function Get-TemporaryAccessPassPolicy {
    <#
    .SYNOPSIS
    Reads the tenant's TemporaryAccessPass authentication method policy constraints
    #>
    $config = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId TemporaryAccessPass
    $props = $config.AdditionalProperties
    
    return [PSCustomObject]@{
        # When true, the tenant forces one-time-use TAPs; otherwise reusable TAPs are allowed
        IsUsableOnce      = [bool]$props.isUsableOnce
        MaxLifetimeMinutes = [int]$props.maximumLifetimeInMinutes
    }
}

function New-TemporaryAccessPass {
    <#
    .SYNOPSIS
    Creates a Temporary Access Pass (TAP) for a user, honoring the tenant's policy constraints
    #>
    param(
        [string]$UserId,
        [bool]$IsUsableOnce,
        [int]$LifetimeMinutes
    )
    
    $tapParams = @{
        startDateTime     = (Get-Date).ToUniversalTime()
        isUsableOnce      = $IsUsableOnce
        lifetimeInMinutes = $LifetimeMinutes
    }
    
    # Newly created users can take a few seconds to replicate before auth methods can be added to them
    $maxAttempts = 5
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $UserId -BodyParameter $tapParams -ErrorAction Stop
            # The TAP code isn't always mapped to a strongly-typed property; fall back to AdditionalProperties
            if ($tap.TemporaryAccessPass) {
                return $tap.TemporaryAccessPass
            }
            return $tap.AdditionalProperties.temporaryAccessPass
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                throw
            }
            Start-Sleep -Seconds ($attempt * 5)
        }
    }
}

function Send-TapViaPwPush {
    <#
    .SYNOPSIS
    Pushes TAP to pwpush and returns share link
    #>
    param(
        [string]$TapCode,
        [string]$AccountUpn
    )
    
    try {
        $response = New-KpPwpush -Payload $TapCode -Note "TAP for $AccountUpn. Delete after use." -ErrorAction Stop
        return $response.html_url
    }
    catch {
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
    ($_.GrantControls.BuiltInControls -contains "mfa") -or
    ($_.GrantControls.BuiltInControls -contains "compliantDevice")
}
    
    foreach ($policy in $mfaPolicies) {
        if ($policy.State -eq "enabled") {
            # Exclude group from policy
            if ($null -eq $policy.Conditions.Users.ExcludeGroups) {
                $policy.Conditions.Users.ExcludeGroups = @()
            }
            
            if ($GroupId -notin $policy.Conditions.Users.ExcludeGroups) {
                $policy.Conditions.Users.ExcludeGroups += $GroupId
                # Only mutable properties may be sent; the full policy object includes read-only fields that fail schema validation
                $updateBody = @{ conditions = $policy.Conditions }
                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $updateBody
            }
        }
    }
}

# Main execution
try {
    # Create 2 break-glass accounts
    $account1 = New-BreakGlassAccount
    $account2 = New-BreakGlassAccount
    
    # Create TAPs, honoring whatever the tenant's TemporaryAccessPass policy allows
    $tapPolicy = Get-TemporaryAccessPassPolicy
    $tap1 = New-TemporaryAccessPass -UserId $account1.User.Id -IsUsableOnce $tapPolicy.IsUsableOnce -LifetimeMinutes $tapPolicy.MaxLifetimeMinutes
    $tap2 = New-TemporaryAccessPass -UserId $account2.User.Id -IsUsableOnce $tapPolicy.IsUsableOnce -LifetimeMinutes $tapPolicy.MaxLifetimeMinutes
    
    # Push TAPs via pwpush
    $tap1Link = Send-TapViaPwPush -TapCode $tap1 -AccountUpn $account1.User.UserPrincipalName
    $tap2Link = Send-TapViaPwPush -TapCode $tap2 -AccountUpn $account2.User.UserPrincipalName
    
    # Create privileged group
    $group = New-PrivilegedGroup -MemberIds @($account1.User.Id, $account2.User.Id)
    
    # Update Conditional Access Policies
    Update-ConditionalAccessPolicies -GroupId $group.Id
    
    # Output summary
    Write-Host "`n=== Break Glass Setup Complete ===" -ForegroundColor Green
    Write-Host "Account 1: $($account1.User.UserPrincipalName)"
    Write-Host "  Password: [REDACTED]"
    Write-Host "  TAP Link: $tap1Link"
    Write-Host ""
    Write-Host "Account 2: $($account2.User.UserPrincipalName)"
    Write-Host "  Password: [REDACTED]"
    Write-Host "  TAP Link: $tap2Link"
    Write-Host ""
    Write-Host "Group: psg-ice ($($group.Id))"
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Share TAP links with end users securely"
    Write-Host "2. Users authenticate and register passkeys"
    Write-Host "3. Assign Global Administrator role to both accounts"
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}
