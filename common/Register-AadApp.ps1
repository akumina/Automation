<#
.SYNOPSIS
    Registers an Entra ID (Azure AD) application with a predefined set of API
    permissions, creates a client secret, adds a Web redirect URI, exposes an
    API (api://<clientId>) and publishes two delegated scopes (access_as_user,
    User.Read).

.DESCRIPTION
    Permissions, scopes and the exposed-API configuration are taken from the
    supplied screenshots:
      * Microsoft Graph                          (29 permissions)
      * Office 365 SharePoint Online             (13 permissions)
      * Microsoft Mobile Application Management  (1 permission)

    Permission GUIDs are NOT hard-coded. The script resolves them at runtime by
    reading the oauth2PermissionScopes (Delegated) and appRoles (Application) of
    each resource service principal in the target tenant, so it stays correct
    even if Microsoft renames or re-IDs anything.

.PARAMETER AppName
    Display name of the application registration to create.

.PARAMETER RedirectUri
    Web platform redirect URI to add (e.g. https://myapp.contoso.com/signin-oidc).

.PARAMETER SecretValidityMonths
    Lifetime of the generated client secret, in months. Default = 12.

.PARAMETER GrantAdminConsent
    If supplied, the script creates a service principal for the app and grants
    tenant-wide admin consent for every requested permission (matches the
    "Granted for ..." state shown in the screenshots). Requires an admin account.

.EXAMPLE
    .\Register-AadApp.ps1 -AppName "Akumina Digital Workplace" `
                          -RedirectUri "https://app.akumina.com/signin-oidc" `
                          -GrantAdminConsent

.NOTES
    Requires the Microsoft.Graph PowerShell SDK. Run as a user able to create
    app registrations (Application Administrator / Cloud Application
    Administrator), and for -GrantAdminConsent, Privileged Role Administrator
    or Global Administrator.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppName,

    [Parameter(Mandatory = $true)]
    [string]$RedirectUri,

    [Parameter(Mandatory = $false)]
    [int]$SecretValidityMonths = 12,

    [Parameter(Mandatory = $false)]
    [switch]$GrantAdminConsent
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 0. Ensure the Microsoft Graph SDK is present and connect
# ---------------------------------------------------------------------------
$requiredModules = @(
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Identity.DirectoryManagement'
)
foreach ($m in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Installing module $m ..." -ForegroundColor Yellow
        Install-Module $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $m -ErrorAction Stop
}

$connectScopes = @('Application.ReadWrite.All', 'Directory.Read.All')
if ($GrantAdminConsent) {
    $connectScopes += @('AppRoleAssignment.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All')
}

Write-Host "Connecting to Microsoft Graph ..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $connectScopes -NoWelcome

# ---------------------------------------------------------------------------
# 1. Define the permission catalogue (resource appId + value + type)
#    Type: "Scope" = Delegated, "Role" = Application
# ---------------------------------------------------------------------------
$GraphAppId      = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
$SharePointAppId = '00000003-0000-0ff1-ce00-000000000000'   # Office 365 SharePoint Online
$MamAppId        = '0000000a-0000-0000-c000-000000000000'   # Microsoft Mobile Application Management

$permissionCatalogue = @(
    # ---------------- Microsoft Graph - Delegated ----------------
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Acronym.Read.All';                 Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Bookmark.Read.All';                Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Calendars.Read';                   Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Calendars.ReadWrite';              Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Channel.ReadBasic.All';            Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'ChannelMessage.Read.All';          Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Chat.Read';                        Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Directory.AccessAsUser.All';       Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'ExternalConnection.Read.All';      Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'ExternalItem.Read.All';            Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Files.Read.All';                   Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Mail.Read';                        Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'MailboxSettings.ReadWrite';        Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Presence.Read';                    Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Presence.Read.All';                Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'SearchConfiguration.ReadWrite.All';Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Sites.Read.All';                   Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Tasks.Read';                       Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Team.ReadBasic.All';               Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'User.Read';                        Type = 'Scope' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'User.Read.All';                    Type = 'Scope' }
    # ---------------- Microsoft Graph - Application ----------------
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Calendars.Read';                   Type = 'Role' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Directory.Read.All';               Type = 'Role' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Directory.ReadWrite.All';          Type = 'Role' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Group.ReadWrite.All';              Type = 'Role' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Sites.FullControl.All';            Type = 'Role' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Sites.Manage.All';                 Type = 'Role' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'Sites.Read.All';                   Type = 'Role' }
    [pscustomobject]@{ Resource = $GraphAppId; Value = 'User.Read.All';                    Type = 'Role' }

    # ---------------- SharePoint - Delegated ----------------
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'AllSites.FullControl';        Type = 'Scope' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'AllSites.Manage';             Type = 'Scope' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'AllSites.Read';               Type = 'Scope' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'MyFiles.Read';                Type = 'Scope' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'MyFiles.Write';               Type = 'Scope' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'Sites.Search.All';            Type = 'Scope' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'TermStore.ReadWrite.All';     Type = 'Scope' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'User.ReadWrite.All';          Type = 'Scope' }
    # ---------------- SharePoint - Application ----------------
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'Sites.Manage.All';            Type = 'Role' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'Sites.Read.All';              Type = 'Role' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'TermStore.Read.All';          Type = 'Role' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'User.Read.All';               Type = 'Role' }
    [pscustomobject]@{ Resource = $SharePointAppId; Value = 'User.ReadWrite.All';          Type = 'Role' }

    # ---------------- Microsoft Mobile Application Management - Delegated ----------------
    [pscustomobject]@{ Resource = $MamAppId;        Value = 'DeviceManagementManagedApps.ReadWrite'; Type = 'Scope' }
)

# ---------------------------------------------------------------------------
# 2. Resolve each resource service principal once and cache its scopes/roles
# ---------------------------------------------------------------------------
Write-Host "Resolving resource service principals & permission IDs ..." -ForegroundColor Cyan
$resourceCache = @{}
foreach ($resAppId in ($permissionCatalogue.Resource | Select-Object -Unique)) {
    $sp = Get-MgServicePrincipal -Filter "appId eq '$resAppId'" `
            -Property 'id,appId,displayName,oauth2PermissionScopes,appRoles' `
            -ErrorAction SilentlyContinue
    if (-not $sp) {
        throw "Resource service principal with appId '$resAppId' was not found in this tenant. The corresponding service (Graph / SharePoint / Intune MAM) may need to be enabled first."
    }
    $resourceCache[$resAppId] = $sp
}

# ---------------------------------------------------------------------------
# 3. Build the requiredResourceAccess collection (grouped by resource)
# ---------------------------------------------------------------------------
$grouped = $permissionCatalogue | Group-Object Resource
$requiredResourceAccess = foreach ($g in $grouped) {
    $sp = $resourceCache[$g.Name]
    if (-not $sp -or [string]::IsNullOrWhiteSpace($g.Name)) {
        Write-Warning "Skipping a resource group with no resolved service principal (name='$($g.Name)')."
        continue
    }
    $accessList = foreach ($perm in $g.Group) {
        if ($perm.Type -eq 'Scope') {
            $found = $sp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $perm.Value }
        }
        else {
            $found = $sp.AppRoles | Where-Object { $_.Value -eq $perm.Value }
        }
        if (-not $found) {
            Write-Warning "Could not resolve $($perm.Type) '$($perm.Value)' on resource '$($sp.DisplayName)'. Skipping."
            continue
        }
        @{ Id = $found.Id; Type = $perm.Type }
    }
    if (@($accessList).Count -eq 0) { continue }
    @{
        ResourceAppId  = $g.Name
        ResourceAccess = @($accessList)
    }
}

if (@($requiredResourceAccess).Count -eq 0) {
    throw "No permissions could be resolved. Aborting before creating the application."
}

# ---------------------------------------------------------------------------
# 4. Create the application registration (with Web redirect URI)
# ---------------------------------------------------------------------------
Write-Host "Creating application '$AppName' ..." -ForegroundColor Cyan
$webConfig = @{ RedirectUris = @($RedirectUri) }

$app = New-MgApplication -DisplayName $AppName `
                         -SignInAudience 'AzureADMyOrg' `
                         -Web $webConfig `
                         -RequiredResourceAccess $requiredResourceAccess

$clientId = $app.AppId
Write-Host "  Application (client) ID : $clientId" -ForegroundColor Green
Write-Host "  Object ID               : $($app.Id)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Expose an API: set identifier URI api://<clientId> and publish scopes
# ---------------------------------------------------------------------------
Write-Host "Configuring 'Expose an API' (api://$clientId) ..." -ForegroundColor Cyan

function New-DelegatedScope {
    param([string]$Name)
    return @{
        Id                      = [guid]::NewGuid().ToString()
        Value                   = $Name
        Type                    = 'Admin'        # "Admins only" can consent
        IsEnabled               = $true
        AdminConsentDisplayName = $Name
        AdminConsentDescription = "Allow the application to $Name on behalf of the signed-in user."
        UserConsentDisplayName  = $null
        UserConsentDescription  = $null
    }
}

$apiScopes = @(
    (New-DelegatedScope -Name 'access_as_user'),
    (New-DelegatedScope -Name 'User.Read')
)

$apiConfig = @{
    Oauth2PermissionScopes = $apiScopes
    RequestedAccessTokenVersion = 2
}

Update-MgApplication -ApplicationId $app.Id `
                     -IdentifierUris @("api://$clientId") `
                     -Api $apiConfig

Write-Host "  Application ID URI : api://$clientId" -ForegroundColor Green
Write-Host "  Scopes published   : access_as_user, User.Read" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6. Create a client secret
# ---------------------------------------------------------------------------
Write-Host "Creating client secret ..." -ForegroundColor Cyan
$passwordCred = @{
    DisplayName = "$AppName-secret"
    EndDateTime = (Get-Date).AddMonths($SecretValidityMonths)
}
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $passwordCred

# ---------------------------------------------------------------------------
# 7. (Optional) Create the service principal and grant admin consent
# ---------------------------------------------------------------------------
if ($GrantAdminConsent) {
    Write-Host "Granting tenant-wide admin consent ..." -ForegroundColor Cyan
    try {
        $clientSp = Get-MgServicePrincipal -Filter "appId eq '$clientId'" -ErrorAction SilentlyContinue
        if (-not $clientSp) {
            $clientSp = New-MgServicePrincipal -AppId $clientId
        }
        # Graph eventual-consistency: give the SP a moment to propagate
        Start-Sleep -Seconds 10

        foreach ($g in $grouped) {
            $resourceSp = $resourceCache[$g.Name]

            # ----- Delegated permissions: one oauth2PermissionGrant per resource -----
            $delegated = $g.Group | Where-Object { $_.Type -eq 'Scope' } | ForEach-Object { $_.Value }
            if ($delegated.Count -gt 0) {
                $existing = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($clientSp.Id)' and resourceId eq '$($resourceSp.Id)'" -ErrorAction SilentlyContinue
                $params = @{
                    ClientId    = $clientSp.Id
                    ConsentType = 'AllPrincipals'
                    ResourceId  = $resourceSp.Id
                    Scope       = ($delegated -join ' ')
                }
                if ($existing) {
                    Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $existing.Id -Scope $params.Scope
                }
                else {
                    New-MgOauth2PermissionGrant -BodyParameter $params | Out-Null
                }
            }

            # ----- Application permissions: one app role assignment per role -----
            $appRoles = $g.Group | Where-Object { $_.Type -eq 'Role' }
            foreach ($r in $appRoles) {
                $roleDef = $resourceSp.AppRoles | Where-Object { $_.Value -eq $r.Value }
                if ($roleDef) {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $clientSp.Id `
                        -PrincipalId $clientSp.Id `
                        -ResourceId  $resourceSp.Id `
                        -AppRoleId   $roleDef.Id -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
        Write-Host "  Admin consent granted." -ForegroundColor Green
    }
    catch {
        Write-Warning "Admin consent step failed: $($_.Exception.Message)"
        Write-Warning "You can still grant consent in the portal: App registrations > $AppName > API permissions > Grant admin consent."
    }
}

# ---------------------------------------------------------------------------
# 8. Output summary  (COPY THE SECRET NOW - it cannot be retrieved later)
# ---------------------------------------------------------------------------
$tenantId = (Get-MgContext).TenantId

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  APP REGISTRATION COMPLETE" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ("  Display name        : {0}" -f $AppName)
Write-Host ("  Tenant ID           : {0}" -f $tenantId)
Write-Host ("  Application (client) ID : {0}" -f $clientId)
Write-Host ("  Object ID           : {0}" -f $app.Id)
Write-Host ("  Application ID URI   : api://{0}" -f $clientId)
Write-Host ("  Web redirect URI     : {0}" -f $RedirectUri)
Write-Host ("  Secret expires       : {0:yyyy-MM-dd}" -f $passwordCred.EndDateTime)
Write-Host ""
Write-Host "  >>> CLIENT SECRET (copy now, shown only once) <<<" -ForegroundColor Yellow
Write-Host ("  {0}" -f $secret.SecretText) -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Magenta

# Also emit an object so the values can be piped / captured programmatically
[pscustomobject]@{
    DisplayName      = $AppName
    TenantId         = $tenantId
    ClientId         = $clientId
    ObjectId         = $app.Id
    ApplicationIdUri = "api://$clientId"
    RedirectUri      = $RedirectUri
    ClientSecret     = $secret.SecretText
    SecretExpires    = $passwordCred.EndDateTime
}
