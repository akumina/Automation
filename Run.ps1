#Pre-req:
# 1.	Windows Server 2016/10 Powershell version 5.1 already installed
#       Windows Server 2012R2 download Workforce Management (WFM) package from https://docs.microsoft.com/en-us/powershell/wmf/5.1/install-configure
# 2.    If this is the first time running, install the AzureRM and AzureAD modules on your local machine using the following commands
#       Install-Module -Name AzureRM -RequiredVersion 6.13.1 -Repository PSGallery
#		OR Run this command to update to required version: Update-Module -Name AzureRM -RequiredVersion 6.13.1 -Repository PSGallery
#		Can also download from https://github.com/Azure/azure-powershell/releases/tag/v6.8.1-August2018
#		Install-Module -Name AzureAD -RequiredVersion 2.0.2.76
# 3.	Optional: If you already installed AzureRM and AzureAD, but keep getting command not found, then the module(s) may not be loaded. You can load them manually by running the following commands
#		Import-Module -Name AzureRM
#		Import-Module -Name AzureAD
# 4.	If you get a certificate error, then you may need to change the execution policy
#		Example commands: Set-ExecutionPolicy RemoteSigned  OR Set-ExecutionPolicy Unrestricted
# 5.	To get a list of Azure server locations, log into your Azure portal, open a PowerShell and run the command Get-AzureRmLocation

$ErrorActionPreference = 'Stop'
cd $PSScriptRoot
$version=$PSVersionTable.PSVersion.Major
if($version -lt 5)
{
    Throw "Version is not supported, please upgrade to 5 or later"
}
if(!(test-path "parameters.json"))
{
	Throw "Parameters file missing, Place the parameters.json file in app installation location"
}
import-module .\Common.psm1

#get-help  Add-AkAppResources
Write-Host "Reading parameters value" -ForegroundColor Cyan 
$jo = Get-Content "parameters.json" | ConvertFrom-Json
$tenantId=Get-AkParams  -params $jo.parameters -param "tenantId" 
$subscriptionId=Get-AkParams  -params $jo.parameters -param "subscriptionId" 
$resourceGroupName=Get-AkParams  -params $jo.parameters -param "resourceGroupName" 
$location=Get-AkParams  -params $jo.parameters -param "location"
$createStorage=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createStorage")
$storageAccountName=""
if($createStorage)	{
	$storageAccountName=Get-AkParams  -params $jo.parameters -param "storageAccountName" 			
}
$createWebApp=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createWebApp")
if($createWebApp)	{		
	if($storageAccountName -eq "")
	{
		Write-Host "Storage account must needed for webapp creation" -ForegroundColor Cyan
		$createStorage = $true
		$storageAccountName=Get-AkParams  -params $jo.parameters -param "storageAccountName" 
	}
	$baseName=Get-AkParams  -params $jo.parameters -param "baseName"
	$localAppDirectory=Get-AkParams  -params $jo.parameters -param "localAppDirectory" 
	$customEmails=Get-AkParams  -params $jo.parameters -param "customEmails" 			
}
$createKeyVault=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createKeyVault" )	
if($createKeyVault)
{
	$keyVaultName=Get-AkParams  -params $jo.parameters -param "keyVaultName"		
}
$createAzureADApp=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createAzureADApp")
if($createAzureADApp)
{
	$aadAppName=Get-AkParams  -params $jo.parameters -param "aadAppName"	
}
$createAppGw=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createAppGw")
if($createAppGw)
{
	$pfxFile=Get-AkParams  -params $jo.parameters -param "pfxFile" 	
	$backendHostName=Get-AkParams  -params $jo.parameters -param "backendHostName" 	
	$vnetAddressPrefix=Get-AkParams  -params $jo.parameters -param "vnetAddressPrefix"	
	$subnetPrefix=Get-AkParams  -params $jo.parameters -param "subnetPrefix"	
}
$createRedisCache=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createRedisCache")
if($createRedisCache)
{
	$RedisCacheName=Get-AkParams  -params $jo.parameters -param "RedisCacheName"
}
$createTrafficManager=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createTrafficManager")
$createDistributionApp=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createDistributionApp")
$createFuncApp=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createFuncApp")
if($createFuncApp)
{
	$createCosmosDb=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createCosmosDb")
	if($storageAccountName -eq "")
	{
		$storageAccountName=Get-AkParams  -params $jo.parameters -param "storageAccountName"
	}
	$databaseAccountName=Get-AkParams  -params $jo.parameters -param "databaseAccountName"
	$databaseName=Get-AkParams  -params $jo.parameters -param "databaseName"

	$funcAppQueues=Get-AkParams  -params $jo.parameters -param "funcAppQueues"
	$funcAppName=Get-AkParams  -params $jo.parameters -param "funcAppName"
}
if ($baseName -eq "")
{
	$baseName = $resourceGroupName
}

Add-AkAppResources  -TenantId $tenantId -SubscriptionId $subscriptionId -BaseName $baseName -Location $location -ResourceGroupName $resourceGroupName -AadAppName $aadAppName -StorageAccountName $storageAccountName -KeyVaultName $keyVaultName -LocalAppDirectory $localAppDirectory -CustomEmails $customEmails -CreateAppGw $createAppGw -CreateRedisCache $createRedisCache -RedisCacheName $redisCacheName -CreateTrafficManager $createTrafficManager -PfxFile $pfxFile -BackendHostName $backendHostName -CreateDistributionApp $createDistributionApp -appManagerQueryKey $appManagerQueryKey -vnetAddressPrefix $vnetAddressPrefix -subnetPrefix $subnetPrefix -createWebApp $createWebApp -createAzureADApp $createAzureADApp -createStorage $createStorage -createKeyVault $createKeyVault -createFuncApp $createFuncApp -funcAppQueues $funcAppQueues -createCosmosDb $createCosmosDb -databaseAccountName $databaseAccountName -databaseName $databaseName -funcAppName $funcAppName