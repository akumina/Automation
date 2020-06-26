# Automation
Akumina AppManager/ServiceHub PowerShell and ARM template based installation.

Current Version: v5-preview  (AppManager and PeopleSync)

For previous verions (ex., 4.5 or 4.8): 

You can still use the same scripts but in the parameters.json set "createFuncApp" to "n"

If you use this script to create Aad App and Set require permissions for PeopleSync (4.8 or earlier) then the following scope commented, you may need to uncomment the following lines in common.psm1
#$appId = "00000002-0000-0000-c000-000000000000"
#$appPermissions = "Directory.Read.All"
#$deligatedPermission = ""
#$wadRequiredPermissions = Get-AkRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
#$requiredResourcesAccess.Add($wadRequiredPermissions)  

