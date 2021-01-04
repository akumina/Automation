# Automation


## Akumina AppManager/ServiceHub PowerShell and ARM template based installation.

**Current Version:** AppManager 5.0; PeopleSync 5.0
# ARM Template
ARM Templates can be executed using powershell or DevOps pipeline
The following are optional parameters
packageUri - Zip file contains all web app files, if provided it will deploy the site files
redisCacheName - If this value is empty then Redis cache provisioning step will be skipped

# Azure Blueprint

Blueprint scripts creates required services only.  All configuration should be updated manually.

# PowerShell
**For previous verions (ex., 4.5 or 4.8):**

You can still use the same scripts but in the parameters.json set "createFuncApp" to "n"

If you use this script to create Aad App and Set require permissions for PeopleSync (4.8 or earlier) then the following scope commented, you may need to uncomment the following lines in common.psm1

#$appId = "00000002-0000-0000-c000-000000000000"

#$appPermissions = "Directory.Read.All"

#$deligatedPermission = ""

#$wadRequiredPermissions = Get-AkRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions

#$requiredResourcesAccess.Add($wadRequiredPermissions)  