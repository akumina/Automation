#Pre-req:
# 1.	Windows Server 2016/10 Powershell version 5.1 already installed
#       Windows Server 2012R2 download Workforce Management (WFM) package from https://docs.microsoft.com/en-us/powershell/wmf/5.1/install-configure
# 2.    If this is the first time running, install the AzureRM and AzureAD modules on your local machine using the following commands
#       Install-Module -Name AzureRM -RequiredVersion 6.13.1 -Repository PSGallery
#		OR Run this command to update to required version: Update-Module -Name AzureRM -RequiredVersion 6.13.1 -Repository PSGallery
#		Can also download from https://github.com/Azure/azure-powershell/releases/tag/v6.8.1-Auust2018
#		Install-Module -Name AzureAD -RequiredVersion 2.0.1.10
# 3.	Optional: If you already installed AzureRM and AzureAD, but keep getting command not found, then the module(s) may not be loaded. You can load them manually by running the following commands
#		Import-Module -Name AzureRM
#		Import-Module -Name AzureAD
# 4.	If you get a certificate error, then you may need to change the execution policy
#		Example commands: Set-ExecutionPolicy RemoteSigned  OR Set-ExecutionPolicy Unrestricted
# 5.	To get a list of Azure server locations, log into your Azure portal, open a PowerShell and run the command Get-AzureRmLocation

$ErrorActionPreference = 'Stop'

$version=$PSVersionTable.PSVersion.Major
if($version -lt 5)
{
    Throw "Version is not supported, please upgrade to 5 or later"
}

import-module .\Common.psm1

#get-help  Provision-AkAppResources

$parametersFile = "parameters.json"

if(Test-Path $parametersFile) 
{
	Write-Host "Reading parameters value" -ForegroundColor Cyan
	$jo = Get-Content $parametersFile | ConvertFrom-Json 
    $tenantId=Get-AkParams  -params $jo.parameters -param "tenantId" -displayName "Tenant Id"
	$subscriptionId=Get-AkParams  -params $jo.parameters -param "subscriptionId" -displayName "Subscription Id"
	$resourceGroupName=Get-AkParams  -params $jo.parameters -param "resourceGroupName" -displayName "Resource Group Name"
	$location=Get-AkParams  -params $jo.parameters -param "location" -displayName "Location"
	$createStorage=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createStorage" -displayName "Create Storage Account?")
	if($createStorage)	{
		$storageAccountName=Get-AkParams  -params $jo.parameters -param "storageAccountName" -displayName "Storage Account Name"			
	}
	$createWebApp=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createWebApp" -displayName "Create Webapp?")
	if($createWebApp)	{		
		if($storageAccountName -eq "")
		{
			Write-Host "Storage account must needed for webapp creation" -ForegroundColor Cyan
			$createStorage = $true
			$storageAccountName=Get-AkParams  -params $jo.parameters -param "storageAccountName" -displayName "Storage Account Name"
		}
		$baseName=Get-AkParams  -params $jo.parameters -param "baseName" -displayName "Webapp Name"
		$localAppDirectory=Get-AkParams  -params $jo.parameters -param "localAppDirectory" -displayName "Local location for webapp files upload"
		$customEmails=Get-AkParams  -params $jo.parameters -param "customEmails" -displayName "Notification Email"			
	}
	$createAKeyVault=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createAKeyVault" -displayName "Create keyVault?")	
	if($createAKeyVault)
	{
		$keyVaultName=Get-AkParams  -params $jo.parameters -param "keyVaultName" -displayName "keyVault Name"		
	}
	$createAzureADApp=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createAzureADApp" -displayName "Create AzureADApp?")
	if($createAzureADApp)
	{
		$aadAppName=Get-AkParams  -params $jo.parameters -param "aadAppName" -displayName "AzureADApp Name"	
	}
	$createAppGw=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createAppGw" -displayName "Create AzureADApp?")
	if($createAppGw)
	{
		$pfxFile=Get-AkParams  -params $jo.parameters -param "pfxFile" -displayName "pfxFile file"	
		$backendHostName=Get-AkParams  -params $jo.parameters -param "backendHostName" -displayName "Backend HostName"	
		$vnetAddressPrefix=Get-AkParams  -params $jo.parameters -param "vnetAddressPrefix" -displayName "vnetAddressPrefix"	
		$subnetPrefix=Get-AkParams  -params $jo.parameters -param "subnetPrefix" -displayName "subnetPrefix"	
	}
	$createRedisCache=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createRedisCache" -displayName "Create RedisCache?")
	if($createRedisCache)
	{
		$RedisCacheName=Get-AkParams  -params $jo.parameters -param "RedisCacheName" -displayName "RedisCache Name"
	}
	$createTrafficManager=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createTrafficManager" -displayName "Create TrafficManager?")
	$createDistributionApp=Convert-AkInput(Get-AkParams  -params $jo.parameters -param "createDistributionApp" -displayName "Create DistributionApp?")
	if($createDistributionApp)
	{
		$functionAppName=Get-AkParams  -params $jo.parameters -param "functionAppName" -displayName "Function AppName"
		$distributionConnectionName=Get-AkParams  -params $jo.parameters -param "distributionConnectionName" -displayName "Distribution Connection Name"
		$distributionQueneName=Get-AkParams  -params $jo.parameters -param "distributionQueneName" -displayName "Distribution QueneName"
		if($storageAccountName -eq "")
		{
			$storageAccountName=Get-AkParams  -params $jo.parameters -param "storageAccountName" -displayName "Storage Account Name"
		}
		if($keyVaultName -eq "")
		{
			$keyVaultName=Get-AkParams  -params $jo.parameters -param "keyVaultName" -displayName "keyVault Name"
		}
		$appManagerQueryKey=Get-AkParams  -params $jo.parameters -param "appManagerQueryKey" -displayName "AppManager Query Key"
		$distributionApiUrl=Get-AkParams  -params $jo.parameters -param "distributionApiUrl" -displayName "AppManager distribution Url"
	}		
	if ($baseName -eq "")
	{
		$baseName = $resourceGroupName
	}
	Add-AkAppResources  -TenantId $tenantId -SubscriptionId $subscriptionId -BaseName $baseName -Location $location -ResourceGroupName $resourceGroupName -AadAppName $aadAppName -StorageAccountName $storageAccountName -KeyVaultName $keyVaultName -LocalAppDirectory $localAppDirectory -CustomEmails $customEmails -CreateAppGw $createAppGw -CreateRedisCache $createRedisCache -RedisCacheName $redisCacheName -CreateTrafficManager $createTrafficManager -PfxFile $pfxFile -BackendHostName $backendHostName -CreateDistributionApp $createDistributionApp -appManagerQueryKey $appManagerQueryKey -distributionApiUrl $distributionApiUrl -DistributionAppDirectory $distributionAppDirectory -FunctionAppName $functionAppName	-vnetAddressPrefix $vnetAddressPrefix -subnetPrefix $subnetPrefix -createWebApp $createWebApp -createAzureADApp $createAzureADApp -createStorage $createStorage -createAKeyVault $createAKeyVault -akDistributionKeyVaultUri $distributionConnectionName -distributionQueneName $distributionQueneName
}
else
{
    Write-Host "Parameters file missing, Place the parameters.json file in app installation location"
}