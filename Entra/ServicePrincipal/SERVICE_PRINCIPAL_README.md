# Service Principal Setup

`CreateServicePrincipal.ps1` creates or updates the Microsoft Entra application and
service principal used by assessment and automation scripts in this repository.
It is not tied to a particular assessment framework.

The script supports two permission modes:

- **Assessment mode**: read-only Microsoft Graph application permissions.
- **Full mode**: the assessment permissions plus the write permissions required by
  tools that create or update directory objects, policies, groups, or
  authentication settings.

Use the least-privileged mode that supports the work you need to perform.

## Prerequisites

Run the script from PowerShell 7 or later. The account running it must be a
Microsoft Entra **Application Administrator** or **Global Administrator**.
Admin consent is granted while the script runs, so the account must also be
allowed to grant the selected Microsoft Graph application permissions.

Install the required modules if they are not already available:

```powershell
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Applications -Scope CurrentUser
```

The script also requires the `zip` command on macOS/Linux. On Windows, install
[7-Zip](https://www.7-zip.org/) to create an encrypted ZIP. Windows
`Compress-Archive` does not support password protection and is used as an
unencrypted fallback if 7-Zip is not installed.

## Quick start

Open PowerShell in this directory and run **exactly one** of these commands.

### Read-only assessment access

```powershell
.\CreateServicePrincipal.ps1 -AssessmentMode
```

Use this mode when the tools only need to inspect the tenant.

### Read/write access

```powershell
.\CreateServicePrincipal.ps1 -FullMode
```

Use this mode only when the tools need to make changes. The script upgrades the
existing application’s permissions when switching from assessment mode to full
mode.

Do not specify both switches. Always specify one explicitly; omitting both is
not a supported way to select a mode.

## What the script does

The script:

1. Connects to Microsoft Graph interactively.
2. Finds or creates the application registration named `sp-onevinn`.
3. Finds or creates the corresponding service principal.
4. Sets the application permissions for the selected mode.
5. Grants admin consent for those permissions.
6. Reuses the current client secret when a matching local credential file is
   available; otherwise, creates a new secret valid for 30 days.
7. Writes the credentials to `auth.json`.
8. Creates `auth.zip` for secure transfer and removes the unencrypted
   `auth.json` when the ZIP is created.

The application permissions are defined in
[`CreateServicePrincipal.ps1`](./CreateServicePrincipal.ps1). The script is the
source of truth because the permission set can change as supported assessment
tools evolve.

## Output and credential handling

On a successful run, the files are written beside the script:

- `auth.zip`: credential package intended for the operator or consultant using
  the assessment tools.
- `auth.json`: temporary unencrypted credential file. It is removed after a
  successful ZIP creation when the ZIP is present.

The credential file contains:

```json
{
  "TenantId": "tenant-id",
  "ClientId": "application-client-id",
  "ClientSecret": "client-secret",
  "ExpiryDate": "yyyy-mm-dd",
  "Mode": "Assessment",
  "LastUpdated": "yyyy-mm-dd HH:mm:ss",
  "SecretStatus": "NewlyCreated"
}
```

Treat `auth.zip`, `auth.json`, and the client secret as sensitive credentials.
Share the ZIP and its password through separate secure channels. Do not send
credentials through public or unencrypted chat, commit them to source control,
or upload them to an unapproved location.

On macOS/Linux, the script uses the system `zip` command to encrypt the package.
On Windows, it uses 7-Zip when available. If the Windows fallback is used, the
ZIP is **not encrypted**; stop and install 7-Zip before sharing that file.

## Re-running the script

The script is safe to run again for the same application:

- Existing applications and service principals are reused.
- Existing managed permissions are updated to match the selected mode.
- A valid secret is reused only when the matching `auth.json` is available.
- If the secret cannot be reused, the script prompts before creating a new one.
- A new secret replaces the previous ZIP. A reused secret does not recreate the
  ZIP, so keep the existing ZIP if it is still required.

Because Microsoft Graph does not return an existing client secret value, losing
the matching `auth.json`/`auth.zip` means a new secret must be created.

## Using the credentials

Extract `auth.json` only on the machine that will run the assessment or
automation tool. Configure that tool to use service principal authentication
and provide the values for `TenantId`, `ClientId`, and `ClientSecret`.

The selected mode controls what the service principal can do:

- Use **Assessment** for inventory, reporting, and read-only analysis.
- Use **Full** only for workflows that require changes.

Review the permissions listed by the script during execution and verify that
they match the intended task before proceeding.

## Cleanup

After the work is complete:

- Delete `auth.zip` and any extracted `auth.json` copies.
- Remove copies from email, cloud storage, downloads, and recycle bins.
- Remove the application registration and service principal if they are no
  longer needed:
  **Microsoft Entra admin center → App registrations → `sp-onevinn` → Delete**.
- If the principal must remain, remove or reduce its permissions and rotate the
  secret before the next engagement.

## Troubleshooting

### Required module is missing

Install the modules listed in [Prerequisites](#prerequisites), then run the
script again.

### The script cannot grant permissions

Confirm that the signed-in account is an Application Administrator or Global
Administrator and can grant admin consent. A Global Administrator can also
grant consent manually from the application’s **API permissions** page, after
which the script can be run again.

### `auth.json` is not found when re-running

The secret value cannot be recovered from Microsoft Entra ID. Restore the
matching credential file from a secure backup, or approve creation of a new
client secret when prompted.

### The ZIP is not password-protected

On Windows, install 7-Zip and run the script again so it can create an
encrypted ZIP. Do not share an unencrypted fallback ZIP.

## References

- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/graph/powershell/overview)
- [Microsoft Entra application and service principal objects](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
