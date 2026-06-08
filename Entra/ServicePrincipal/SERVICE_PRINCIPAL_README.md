# Service Principal Authentication for Phishing Resistant MFA Project

This guide explains how to set up and use service principal authentication.

## Quick Start

### Step 1: Create Service Principal

#### For Assessment Mode (Read-Only)
```powershell
.\CreateServicePrincipal.ps1 -AssessmentMode
```

#### For Full Mode (Read-Write)
```powershell
.\CreateServicePrincipal.ps1
```

This script will:
- Create an Entra ID application
- Create a service principal
- Grant required permissions
- Generate a client secret (30-day expiration)
- Save credentials to `auth.json`
- **Automatically create password-protected `auth.zip`**
- Delete unencrypted `auth.json` for security

✅ **Result**: A secure `auth.zip` file ready for transfer

### Step 2: Share the Credentials

After running the script, you'll have an `auth.zip` file in the same directory.

#### Option A: Email
1. Attach `auth.zip` to an email
2. Send to the designated recipient

#### Option B: OneDrive/SharePoint
1. Upload `auth.zip` to OneDrive or SharePoint
2. Create a sharing link with **7-day expiration**
3. Share the link

⚠️ **Important**: 
- The ZIP file is already password-protected
- **Do NOT** send the file via unencrypted chat/messaging apps


### Step 3: After Engagement Cleanup

**Important**: Clean up after the engagement is complete:

- [ ] Delete `auth.zip` from your machine
- [ ] Delete from email inbox/sent items
- [ ] Delete from OneDrive/SharePoint
- [ ] Empty Recycle Bin / Deleted Items
- [ ] (Optional) Delete service principal from Entra ID:
  - Azure Portal → App registrations → `sp-onevinn-prmfa` → Delete

## What's in the Secure Package?

The `auth.zip` file is password-protected and contains `auth.json` with:
- `tenantId`: Your Azure tenant ID
- `clientId`: The application client ID
- `clientSecret`: The client secret (sensitive!)
- `applicationId`: The application's object ID
- `servicePrincipalId`: The service principal's object ID
- `createdDate`: When the credentials were created
- `expiresDate`: When the client secret expires

**Example structure:**
```json
{
  "tenantId": "12345678-1234-1234-1234-123456789012",
  "clientId": "abcdef01-2345-6789-abcd-ef0123456789",
  "clientSecret": "Your_Secret_Here",
  "applicationId": "f1234567-1234-1234-1234-123456789abc",
  "servicePrincipalId": "s1234567-1234-1234-1234-123456789def",
  "createdDate": "2024-02-03 14:30:00",
  "expiresDate": "2026-02-03 14:30:00"
}
```

## Renewing Service Principal Secret

When the client secret approaches expiration:

```powershell
# Run the creation script again with -Renew parameter (if you extend the script)
# Or manually:
# 1. Delete auth.json
# 2. Run CreateServicePrincipal.ps1 again
```

## Troubleshooting

### "auth.json not found" error
```powershell
# If using ServicePrincipal mode, run the creation script first:
.\CreateServicePrincipal.ps1
```

### "Service Principal authentication failed"
- Verify `auth.json` exists and is valid JSON
- Check that the client secret hasn't expired
- Run CreateServicePrincipal.ps1 to create new credentials
- Verify tenant ID is correct

### "User authentication failed"
- Your credentials may not have required permissions
- Check that you have one of these roles:
  - Global Administrator
  - Conditional Access Administrator + Groups Administrator + Security Administrator

### Permission errors during execution
- Service principal may not have been granted proper consent
- Run CreateServicePrincipal.ps1 again
- Grant admin consent manually in Azure Portal if needed

## Required Permissions

Both user and service principal authentication require these Microsoft Graph scopes:
- `Group.ReadWrite.All` - Create and manage groups
- `Policy.ReadWrite.ConditionalAccess` - Create CA policies
- `Policy.Read.All` - Read policies
- `User.Read.All` - Read user information
- `RoleManagement.Read.Directory` - Check user roles
- `Policy.ReadWrite.AuthenticationMethod` - Configure auth methods

## PowerShell Version Requirements

- PowerShell 7.0+ (Core/Windows PowerShell may have compatibility issues)
- Microsoft Graph PowerShell SDK modules installed

## Support

For issues with the service principal setup, refer to:
- [Microsoft Graph PowerShell SDK Documentation](https://learn.microsoft.com/en-us/graph/powershell/overview)
- [Service Principal Authentication Guide](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals)
- [Conditional Access Policy Documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/)
