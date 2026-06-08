#Requires -Version 7.0
<#
.SYNOPSIS
    Creates or updates a service principal using certificate-based authentication.

.DESCRIPTION
    Creates or updates a service principal using certificate-based authentication for the
    Phishing Resistant MFA framework. The private key never leaves the device (machine
    certificate store or hardware security module such as a YubiKey).

    CERTIFICATE INPUT OPTIONS:
    Provide exactly one of:
    - CertificatePath:   Path to a .cer, .pem, or .crt file containing the public key
    - CertificateBase64: Base64-encoded DER bytes of the public certificate
    - Thumbprint:        Thumbprint of a certificate already present in the user's
                         certificate store (CurrentUser\My)

    ASSESSMENT MODE (-AssessmentMode):
    Creates a service principal with READ-ONLY permissions suitable for assessments.

    FULL MODE (default):
    Creates or upgrades a service principal with READ-WRITE permissions for
    enrollment and enforcement.

    The script:
    - Checks for an existing application and reuses it
    - Detects valid non-expired certificates and reuses them
    - Upgrades permissions when switching from assessment to full mode
    - Grants admin consent automatically
    - Exports credentials to auth.json (TenantId, ClientId, CertificateThumbprint)

    Because the private key stays on the device, there is no secret to share and no ZIP
    file is created.

.PARAMETER CertificatePath
    Path to a .cer, .pem, or .crt file that contains the public certificate.

.PARAMETER CertificateBase64
    Base64-encoded DER representation of the public certificate.

.PARAMETER Thumbprint
    Thumbprint of a certificate already in the CurrentUser\My store. The public key
    will be read from the store and uploaded to the app registration.

.PARAMETER AssessmentMode
    When specified, creates service principal with read-only permissions.
    When omitted, creates or upgrades to full read-write permissions.

.NOTES
    Requirements:
    - User must have Application Administrator or Global Administrator role
    - Microsoft.Graph.Applications module
    - Microsoft.Graph.Authentication module

.EXAMPLE
    .\CreateServicePrincipalCertificate.ps1 -CertificatePath .\sp-onevinn-prmfa.cer -AssessmentMode
    # Creates SP with read-only permissions using a .cer file

.EXAMPLE
    .\CreateServicePrincipalCertificate.ps1 -Thumbprint "A1B2C3D4E5..." 
    # Creates/upgrades SP with full permissions using a cert from the local store

.EXAMPLE
    .\CreateServicePrincipalCertificate.ps1 -CertificateBase64 "MIIC..." 
    # Creates SP using a base64-encoded public certificate
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CertificatePath,

    [Parameter(Mandatory = $false)]
    [string]$CertificateBase64,

    [Parameter(Mandatory = $false)]
    [string]$Thumbprint,

    [Parameter(Mandatory = $false)]
    [switch]$AssessmentMode
)

# ============================================================================
# SCRIPT CONFIGURATION
# ============================================================================

$mode = if ($AssessmentMode) { "ASSESSMENT (Read-Only)" } else { "FULL (Read-Write)" }
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Service Principal — Certificate Auth                         ║" -ForegroundColor Cyan
Write-Host "║  Mode: $(($mode).PadRight(50)) ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# ============================================================================
# VALIDATE EXACTLY ONE CERTIFICATE INPUT
# ============================================================================

$inputCount = @($CertificatePath, $CertificateBase64, $Thumbprint) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Measure-Object | Select-Object -ExpandProperty Count

if ($inputCount -eq 0) {
    # Try reading thumbprint from existing auth.json
    $authJsonPath = Join-Path $PSScriptRoot "auth.json"
    if (Test-Path $authJsonPath) {
        $existingAuth = Get-Content -Path $authJsonPath -Raw | ConvertFrom-Json
        if ($existingAuth.CertificateThumbprint) {
            $Thumbprint = $existingAuth.CertificateThumbprint
            Write-Host "✓ Using thumbprint from auth.json: $Thumbprint" -ForegroundColor Green
        }
    }

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        Write-Host "✗ You must provide exactly one certificate input:" -ForegroundColor Red
        Write-Host "    -CertificatePath   <path to .cer/.pem/.crt file>" -ForegroundColor Yellow
        Write-Host "    -CertificateBase64 <base64-encoded public cert>" -ForegroundColor Yellow
        Write-Host "    -Thumbprint        <thumbprint of cert in CurrentUser\My store>" -ForegroundColor Yellow
        Write-Host "`n  Generate a self-signed certificate:" -ForegroundColor Cyan
        Write-Host '    $cert = New-SelfSignedCertificate -Subject "CN=sp-onevinn-prmfa" `' -ForegroundColor Gray
        Write-Host '        -CertStoreLocation "Cert:\CurrentUser\My" `' -ForegroundColor Gray
        Write-Host '        -KeyExportPolicy NonExportable -KeyLength 4096 `' -ForegroundColor Gray
        Write-Host '        -NotAfter (Get-Date).AddMonths(12)' -ForegroundColor Gray
        Write-Host '    Export-Certificate -Cert $cert -FilePath ".\sp-onevinn-prmfa.cer" -Type CERT' -ForegroundColor Gray
        exit 1
    }
}

if ($inputCount -gt 1) {
    Write-Host "✗ Provide only ONE of: -CertificatePath, -CertificateBase64, -Thumbprint" -ForegroundColor Red
    exit 1
}

# ============================================================================
# LOAD CERTIFICATE
# ============================================================================

Write-Host "Loading certificate..." -ForegroundColor Cyan

$publicCert = $null
$publicCertBytes = $null

try {
    if (-not [string]::IsNullOrWhiteSpace($CertificatePath)) {
        # Load from file
        if (-not (Test-Path $CertificatePath)) {
            Write-Host "  ✗ Certificate file not found: $CertificatePath" -ForegroundColor Red
            exit 1
        }
        $fileBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $CertificatePath).Path)
        $publicCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($fileBytes)
        $publicCertBytes = $publicCert.RawData
        Write-Host "  ✓ Loaded from file: $CertificatePath" -ForegroundColor Green
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CertificateBase64)) {
        # Load from base64 string
        $publicCertBytes = [Convert]::FromBase64String($CertificateBase64)
        $publicCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCertBytes)
        Write-Host "  ✓ Loaded from Base64 input" -ForegroundColor Green
    }
    elseif (-not [string]::IsNullOrWhiteSpace($Thumbprint)) {
        # Load from certificate store — OS-aware
        if ($IsWindows -or $env:OS -eq 'Windows_NT') {
            # Windows: use Cert: PSDrive
            $storeCert = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Thumbprint -eq $Thumbprint }
            if (-not $storeCert) {
                Write-Host "  ✗ Certificate with thumbprint '$Thumbprint' not found in CurrentUser\My" -ForegroundColor Red
                Write-Host "    List available certificates: Get-ChildItem Cert:\CurrentUser\My | Select Subject, Thumbprint, NotAfter" -ForegroundColor Yellow
                exit 1
            }
            $publicCert = $storeCert
            $publicCertBytes = $publicCert.RawData
            Write-Host "  ✓ Loaded from certificate store (CurrentUser\My)" -ForegroundColor Green
        }
        else {
            # macOS/Linux: export from Keychain / cert store via subject name in auth.json
            $certSubjectName = $null
            $authJsonFallback = Join-Path $PSScriptRoot "auth.json"
            if (Test-Path $authJsonFallback) {
                $authData = Get-Content -Path $authJsonFallback -Raw | ConvertFrom-Json
                if ($authData.CertificateSubject) {
                    $certSubjectName = $authData.CertificateSubject -replace '^CN=', ''
                }
            }

            $pemData = $null
            if ($IsMacOS -and $certSubjectName) {
                # macOS: export matching cert from Keychain as PEM
                Write-Host "  Searching macOS Keychain for '$certSubjectName'..." -ForegroundColor Gray
                $pemData = security find-certificate -c $certSubjectName -p 2>/dev/null
            }
            elseif ($certSubjectName) {
                # Linux: try certutil or openssl with common paths
                Write-Host "  Searching for certificate '$certSubjectName'..." -ForegroundColor Gray
                $certFile = Get-ChildItem -Path "$HOME/.dotnet/corefx/cryptography/x509stores/my" -Filter "*.pfx" -ErrorAction SilentlyContinue |
                    Select-Object -First 1
                if ($certFile) {
                    $pemData = openssl pkcs12 -in $certFile.FullName -clcerts -nokeys -passin pass: 2>/dev/null
                }
            }

            if ($pemData) {
                $pemString = ($pemData -join "`n")
                $publicCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    [System.Text.Encoding]::UTF8.GetBytes($pemString)
                )

                if ($publicCert.Thumbprint -ne $Thumbprint) {
                    Write-Host "  ⚠ Keychain cert thumbprint ($($publicCert.Thumbprint)) doesn't match auth.json ($Thumbprint)" -ForegroundColor Yellow
                    Write-Host "    The certificate may have been regenerated. Continuing with Keychain cert." -ForegroundColor Yellow
                }

                $publicCertBytes = $publicCert.RawData
                Write-Host "  ✓ Loaded from $(if ($IsMacOS) { 'macOS Keychain' } else { 'certificate store' })" -ForegroundColor Green
            }
            else {
                Write-Host "  ✗ Certificate not found in $(if ($IsMacOS) { 'macOS Keychain' } else { 'certificate store' })" -ForegroundColor Red
                if ($IsMacOS) {
                    Write-Host "    List Keychain certs: security find-certificate -a -c 'onevinn-prmfa' -Z login.keychain-db" -ForegroundColor Yellow
                    Write-Host "    Or provide the .pem file: -CertificatePath ./sp-onevinn-prmfa.pem" -ForegroundColor Yellow
                }
                exit 1
            }
        }
    }
}
catch {
    Write-Host "  ✗ Failed to load certificate: $_" -ForegroundColor Red
    exit 1
}

# Validate certificate
if ($publicCert.NotAfter -lt (Get-Date)) {
    Write-Host "  ✗ Certificate has expired: $($publicCert.NotAfter.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Red
    exit 1
}

$certThumbprint = $publicCert.Thumbprint
$certSubject = $publicCert.Subject
$certNotBefore = $publicCert.NotBefore
$certNotAfter = $publicCert.NotAfter

Write-Host "  Subject:     $certSubject" -ForegroundColor Gray
Write-Host "  Thumbprint:  $certThumbprint" -ForegroundColor Gray
Write-Host "  Valid from:  $($certNotBefore.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
Write-Host "  Valid until: $($certNotAfter.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray

$daysValid = [math]::Round(($certNotAfter - (Get-Date)).TotalDays, 0)
if ($daysValid -lt 30) {
    Write-Host "  ⚠ Certificate expires in $daysValid days — consider renewing" -ForegroundColor Yellow
}
else {
    Write-Host "  ✓ $daysValid days remaining" -ForegroundColor Green
}

# ============================================================================
# CHECK REQUIRED MODULES
# ============================================================================

Write-Host "`nChecking required PowerShell modules..." -ForegroundColor Cyan

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications"
)

foreach ($modName in $requiredModules) {
    if (Get-Module -ListAvailable -Name $modName) {
        Write-Host "  ✓ $modName" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ $modName is NOT installed" -ForegroundColor Red
        Write-Host "`n  Install it using: Install-Module -Name $modName -Scope CurrentUser`n" -ForegroundColor Yellow
        exit 1
    }
}

# ============================================================================
# DEFINE PERMISSION SETS
# ============================================================================

Write-Host "`nDefining permission sets..." -ForegroundColor Cyan

$microsoftGraphResourceId = "00000003-0000-0000-c000-000000000000"

# Assessment Mode Permissions (Read-Only)
$assessmentPermissions = @(
    @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role"; Name = "User.Read.All" },
    @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role"; Name = "Directory.Read.All" },
    @{ Id = "5b567255-7703-4780-807c-7be8301ae99b"; Type = "Role"; Name = "Group.Read.All" },
    @{ Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"; Type = "Role"; Name = "Policy.Read.All" },
    @{ Id = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"; Type = "Role"; Name = "RoleManagement.Read.Directory" },
    @{ Id = "01e37dc9-c035-40bd-b438-b2879c4870a6"; Type = "Role"; Name = "PrivilegedAccess.Read.AzureADGroup" },
    @{ Id = "7438b122-aefc-4978-80ed-43db9fcc7715"; Type = "Role"; Name = "Device.Read.All" },
    @{ Id = "38d9df27-64da-44fd-b7c5-a6fbac20248f"; Type = "Role"; Name = "UserAuthenticationMethod.Read.All" },
    @{ Id = "b0afded3-3588-46d8-8b3d-9842eff778da"; Type = "Role"; Name = "AuditLog.Read.All" },
    @{ Id = "fb221be6-99f2-473f-bd32-01c6a0e9ca3b"; Type = "Role"; Name = "Policy.ReadWrite.Authorization" }
)

# Additional permissions for Full Mode (Read-Write)
$fullModeAdditionalPermissions = @(
    @{ Id = "62a82d76-70ea-41e2-9197-370581804d09"; Type = "Role"; Name = "Group.ReadWrite.All" },
    @{ Id = "01c0a623-fc9b-48e9-b794-0756f8e8f067"; Type = "Role"; Name = "Policy.ReadWrite.ConditionalAccess" },
    @{ Id = "29c18626-4985-4dcd-85c0-193eef327366"; Type = "Role"; Name = "Policy.ReadWrite.AuthenticationMethod" },
    @{ Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"; Type = "Role"; Name = "RoleManagement.ReadWrite.Directory" },
    @{ Id = "741f803b-c850-494e-b5df-cde7c675a1ca"; Type = "Role"; Name = "User.ReadWrite.All" },
    @{ Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"; Type = "Role"; Name = "Application.Read.All" }
)

$selectedPermissions = if ($AssessmentMode) {
    Write-Host "  Mode: Assessment (Read-Only)" -ForegroundColor Yellow
    $assessmentPermissions
} else {
    Write-Host "  Mode: Full (Assessment + Enrollment/Enforcement)" -ForegroundColor Green
    $assessmentPermissions + $fullModeAdditionalPermissions
}

Write-Host "`n  Permissions to be assigned:" -ForegroundColor Gray
foreach ($perm in $selectedPermissions) {
    Write-Host "    • $($perm.Name)" -ForegroundColor Gray
}

# ============================================================================
# CONNECT TO MICROSOFT GRAPH
# ============================================================================

Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

try {
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -ErrorAction Stop | Out-Null
    Write-Host "  ✓ Successfully connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ Failed to connect to Microsoft Graph" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Red
    exit 1
}

$context = Get-MgContext
Write-Host "  ✓ Authenticated as: $($context.Account)" -ForegroundColor Green
Write-Host "  ✓ Tenant ID: $($context.TenantId)" -ForegroundColor Green

# ============================================================================
# VALIDATE PERMISSIONS
# ============================================================================

Write-Host "`nValidating your permissions..." -ForegroundColor Cyan

try {
    $grantedScopes = $context.Scopes
    $requiredScopes = @("Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All")
    $missingScopes = @()

    foreach ($scope in $requiredScopes) {
        if ($grantedScopes -notcontains $scope) { $missingScopes += $scope }
    }

    if ($missingScopes.Count -gt 0) {
        Write-Host "`n  ✗ Insufficient permissions detected" -ForegroundColor Red
        Write-Host "    Missing scopes:" -ForegroundColor Red
        foreach ($scope in $missingScopes) { Write-Host "      • $scope" -ForegroundColor Red }
        Write-Host "`n  Required roles: Global Administrator or Application Administrator + Privileged Role Administrator" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "  ✓ All required permissions granted" -ForegroundColor Green
}
catch {
    Write-Host "  ⚠ Could not validate permissions — continuing" -ForegroundColor Yellow
}

# ============================================================================
# STEP 1: CREATE OR UPDATE APPLICATION REGISTRATION
# ============================================================================

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  STEP 1: Application Registration                            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$appDisplayName = "sp-onevinn-prmfa"
$app = $null
$reuseCredential = $false

# Build the KeyCredential for the certificate
$keyCredential = @{
    Type           = "AsymmetricX509Cert"
    Usage          = "Verify"
    Key            = $publicCertBytes
    KeyId          = [Guid]::NewGuid()
    DisplayName    = "$appDisplayName ($certSubject)"
    StartDateTime  = $certNotBefore
    EndDateTime    = $certNotAfter
}

try {
    $existingApp = Get-MgApplication -Filter "displayName eq '$appDisplayName'" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($existingApp) {
        $app = $existingApp
        Write-Host "`n⚠  Application already exists: $appDisplayName" -ForegroundColor Yellow
        Write-Host "   Application ID: $($app.AppId)" -ForegroundColor Gray
        Write-Host "   Object ID: $($app.Id)" -ForegroundColor Gray

        # Check if this certificate is already registered
        $existingCerts = @($app.KeyCredentials | Where-Object { $_.Type -eq "AsymmetricX509Cert" })
        $matchingCerts = @($existingCerts | Where-Object {
            # Compare by thumbprint: compute thumbprint of the stored key
            try {
                $stored = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.Key)
                $stored.Thumbprint -eq $certThumbprint
            }
            catch { $false }
        })

        # Deduplicate: if multiple certs share the same thumbprint, keep only the latest-expiring one
        if ($matchingCerts.Count -gt 1) {
            Write-Host "`n   ⚠ Found $($matchingCerts.Count) duplicate certificate(s) with thumbprint $certThumbprint — cleaning up" -ForegroundColor Yellow
            $keepCert = $matchingCerts | Sort-Object EndDateTime -Descending | Select-Object -First 1
            $nonMatchingCerts = @($existingCerts | Where-Object {
                try {
                    $stored = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.Key)
                    $stored.Thumbprint -ne $certThumbprint
                }
                catch { $true }
            })
            $dedupedKeys = @($nonMatchingCerts | Where-Object { $_.EndDateTime -gt (Get-Date) }) + @($keepCert)
            Update-MgApplication -ApplicationId $app.Id -KeyCredentials $dedupedKeys -ErrorAction Stop
            Write-Host "   ✓ Removed $($matchingCerts.Count - 1) duplicate(s), kept 1" -ForegroundColor Green
            $matchingCerts = @($keepCert)
        }

        $matchingCert = $matchingCerts | Select-Object -First 1

        if ($matchingCert -and $matchingCert.EndDateTime -gt (Get-Date)) {
            $daysLeft = [math]::Round(($matchingCert.EndDateTime - (Get-Date)).TotalDays, 1)
            Write-Host "`n   ✓ Certificate already registered on this application" -ForegroundColor Green
            Write-Host "     Thumbprint: $certThumbprint" -ForegroundColor Gray
            Write-Host "     Expires:    $($matchingCert.EndDateTime.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
            Write-Host "     Days left:  $daysLeft" -ForegroundColor Gray
            $reuseCredential = $true
        }
        else {
            # Add the new certificate credential (keep any existing valid ones)
            $validCerts = @($existingCerts | Where-Object { $_.EndDateTime -gt (Get-Date) })
            $updatedKeys = @($validCerts) + @($keyCredential)

            Write-Host "`n   Adding new certificate to application..." -ForegroundColor Cyan
            Update-MgApplication -ApplicationId $app.Id -KeyCredentials $updatedKeys -ErrorAction Stop
            Write-Host "   ✓ Certificate added (thumbprint: $certThumbprint)" -ForegroundColor Green

            if ($validCerts.Count -gt 0) {
                Write-Host "   ℹ $($validCerts.Count) existing valid certificate(s) kept" -ForegroundColor Gray
            }
        }

        # Update required permissions
        Write-Host "`n   Updating permissions to match $mode mode..." -ForegroundColor Cyan

        $resourceAccess = foreach ($perm in $selectedPermissions) {
            @{ Id = $perm.Id; Type = $perm.Type }
        }

        $params = @{
            RequiredResourceAccess = @(
                @{
                    ResourceAppId  = $microsoftGraphResourceId
                    ResourceAccess = @($resourceAccess)
                }
            )
        }

        try {
            Update-MgApplication -ApplicationId $app.Id -BodyParameter $params -ErrorAction Stop
            Write-Host "   ✓ Permissions updated" -ForegroundColor Green
        }
        catch {
            Write-Host "   ✗ Failed to update permissions: $_" -ForegroundColor Red
            throw "Failed to update application permissions."
        }
    }
    else {
        # Create new application with the certificate credential
        Write-Host "`nCreating new application: $appDisplayName..." -ForegroundColor Cyan

        $resourceAccess = foreach ($perm in $selectedPermissions) {
            @{ Id = $perm.Id; Type = $perm.Type }
        }

        $params = @{
            DisplayName            = $appDisplayName
            SignInAudience         = "AzureADMyOrg"
            KeyCredentials         = @($keyCredential)
            RequiredResourceAccess = @(
                @{
                    ResourceAppId  = $microsoftGraphResourceId
                    ResourceAccess = @($resourceAccess)
                }
            )
        }

        $app = New-MgApplication @params -ErrorAction Stop
        Write-Host "   ✓ Created application: $appDisplayName" -ForegroundColor Green
        Write-Host "     Application ID: $($app.AppId)" -ForegroundColor Gray
        Write-Host "     Object ID: $($app.Id)" -ForegroundColor Gray
    }
}
catch {
    Write-Host "`n   ✗ Failed to create/update application: $_" -ForegroundColor Red
    Disconnect-MgGraph | Out-Null
    exit 1
}

# Set current user as owner
try {
    $currentUser = Get-MgUser -UserId $context.Account -ErrorAction Stop
    $existingOwners = @(Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction SilentlyContinue)
    $isAlreadyOwner = $existingOwners | Where-Object { $_.Id -eq $currentUser.Id }

    if ($isAlreadyOwner) {
        Write-Host "`n   ✓ Current user ($($context.Account)) is already owner" -ForegroundColor Gray
    }
    else {
        $ownerParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($currentUser.Id)"
        }
        New-MgApplicationOwnerByRef -ApplicationId $app.Id -BodyParameter $ownerParams -ErrorAction Stop
        Write-Host "`n   ✓ Added current user ($($context.Account)) as owner" -ForegroundColor Green
    }
}
catch {
    Write-Host "`n   ⚠ Could not set app registration owner: $_" -ForegroundColor Yellow
}

# ============================================================================
# STEP 2: CREATE SERVICE PRINCIPAL
# ============================================================================

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  STEP 2: Service Principal                                   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

try {
    $existingSP = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($existingSP) {
        $sp = $existingSP
        Write-Host "`n⚠  Service Principal already exists" -ForegroundColor Yellow
        Write-Host "   Service Principal ID: $($sp.Id)" -ForegroundColor Gray
    }
    else {
        Write-Host "`nCreating Service Principal..." -ForegroundColor Cyan
        $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
        Write-Host "   ✓ Service Principal created" -ForegroundColor Green
        Write-Host "     Service Principal ID: $($sp.Id)" -ForegroundColor Gray
    }
}
catch {
    Write-Host "`n   ✗ Failed to create Service Principal: $_" -ForegroundColor Red
    Disconnect-MgGraph | Out-Null
    exit 1
}

# ============================================================================
# STEP 3: GRANT ADMIN CONSENT
# ============================================================================

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  STEP 3: Admin Consent                                       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nGranting admin consent for permissions..." -ForegroundColor Cyan

try {
    $microsoftGraphSP = Get-MgServicePrincipal -Filter "appId eq '$microsoftGraphResourceId'" | Select-Object -First 1
    $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue

    $grantedCount = 0
    $skippedCount = 0

    foreach ($perm in $selectedPermissions) {
        $alreadyGranted = $existingAssignments | Where-Object { $_.AppRoleId -eq $perm.Id }

        if ($alreadyGranted) {
            Write-Host "   ○ $($perm.Name) - already granted" -ForegroundColor Gray
            $skippedCount++
        }
        else {
            try {
                $params = @{
                    PrincipalId = $sp.Id
                    ResourceId  = $microsoftGraphSP.Id
                    AppRoleId   = $perm.Id
                }
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter $params -ErrorAction Stop | Out-Null
                Write-Host "   ✓ $($perm.Name) - granted" -ForegroundColor Green
                $grantedCount++
            }
            catch {
                if ($_.Exception.Message -match "403|Forbidden|Insufficient privileges") {
                    Write-Host "   ✗ $($perm.Name) - insufficient privileges" -ForegroundColor Red
                }
                else {
                    Write-Host "   ✗ $($perm.Name) - failed: $_" -ForegroundColor Red
                }
            }
        }
    }

    Write-Host "`n   Summary: $grantedCount granted, $skippedCount already existed" -ForegroundColor Cyan

    $failedCount = $selectedPermissions.Count - $grantedCount - $skippedCount
    if ($failedCount -gt 0) {
        Write-Host "`n   ⚠ $failedCount permission(s) failed to grant" -ForegroundColor Yellow
        Write-Host "     Required: AppRoleAssignment.ReadWrite.All or RoleManagement.ReadWrite.Directory" -ForegroundColor Yellow
        Write-Host "     Action: Ask your Global Administrator to grant consent in Azure Portal:" -ForegroundColor Yellow
        Write-Host "       https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.AppId)" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "`n   ✗ Failed to grant admin consent: $_" -ForegroundColor Red
    Write-Host "     You may need to grant consent manually in Azure Portal" -ForegroundColor Yellow
}

# ============================================================================
# STEP 4: EXPORT auth.json
# ============================================================================

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  STEP 4: Export Credentials                                  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

try {
    $authJsonPath = Join-Path $PSScriptRoot "auth.json"

    $authData = @{
        TenantId              = $context.TenantId
        ClientId              = $app.AppId
        CertificateThumbprint = $certThumbprint
        CertificateSubject    = $certSubject
        CertificateExpiry     = $certNotAfter.ToString('yyyy-MM-dd')
        AuthType              = "Certificate"
        Mode                  = if ($AssessmentMode) { "Assessment" } else { "Full" }
        LastUpdated           = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }

    $authData | ConvertTo-Json -Depth 10 | Out-File -FilePath $authJsonPath -Encoding UTF8 -Force

    Write-Host "`n✓ auth.json exported" -ForegroundColor Green
    Write-Host "  Location: $authJsonPath" -ForegroundColor Gray
    Write-Host "  Auth type: Certificate (thumbprint: $certThumbprint)" -ForegroundColor Gray
    Write-Host "`n  ℹ No secret to protect — the private key stays on your device/YubiKey." -ForegroundColor Cyan
    Write-Host "    auth.json only contains the thumbprint needed to locate the certificate." -ForegroundColor Gray
}
catch {
    Write-Host "`n✗ Failed to export credentials: $_" -ForegroundColor Red
}

# ============================================================================
# SUMMARY
# ============================================================================

Disconnect-MgGraph | Out-Null

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Setup Complete — Certificate Auth                           ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`n📋 Application Details:" -ForegroundColor Cyan
Write-Host "   • Application Name:  $appDisplayName" -ForegroundColor White
Write-Host "   • Application ID:    $($app.AppId)" -ForegroundColor White
Write-Host "   • Tenant ID:         $($context.TenantId)" -ForegroundColor White
Write-Host "   • Mode:              $(if ($AssessmentMode) { 'Assessment (Read-Only)' } else { 'Full (Read-Write)' })" -ForegroundColor White
Write-Host "   • Certificate:       $certSubject" -ForegroundColor White
Write-Host "   • Thumbprint:        $certThumbprint" -ForegroundColor White
Write-Host "   • Certificate Expiry: $($certNotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "   • Credential Status:  $(if ($reuseCredential) { 'Reused Existing' } else { 'Newly Registered' })" -ForegroundColor White

Write-Host "`n🔐 Permissions Granted:" -ForegroundColor Cyan
foreach ($perm in $selectedPermissions) {
    Write-Host "   ✓ $($perm.Name)" -ForegroundColor Gray
}
