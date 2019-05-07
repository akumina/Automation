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

#get-help  ProvisionAkWebApp

$parametersFile = "parameters.json"

#Getting information from the json file
#The we pass the output from Get-Content to ConvertFrom-Json Cmdlet
if(Test-Path $parametersFile) 
{
	Write-Host "Reading parameters value"
    $JsonObject = Get-Content $parametersFile | ConvertFrom-Json
    $tenantId= $JsonObject.parameters.tenantId.value
	if($tenantId -eq "")
	{
		$tenantId=read-host $JsonObject.parameters.tenantId.inputMessage
	}
	else { Write-Host "tenantId = " $tenantId }
	$subscriptionId=$JsonObject.parameters.subscriptionId.value
	if($subscriptionId -eq "")
	{
		$subscriptionId=read-host $JsonObject.parameters.subscriptionId.inputMessage
	}
	else { Write-Host "subscriptionId = " $subscriptionId }	
	$resourceGroupName=$JsonObject.parameters.resourceGroupName.value
	if($resourceGroupName -eq "")
	{
		$resourceGroupName=read-host $JsonObject.parameters.resourceGroupName.inputMessage
	}
	else { Write-Host "ResourceGroupName = " $resourceGroupName }
	$location=$JsonObject.parameters.location.value
	if($location -eq "")
	{
		$location=read-host $JsonObject.parameters.location.inputMessage
	}
	else { Write-Host "location = " $location }

	$createStrorage=$JsonObject.parameters.createStrorage.value
	if($createStrorage -eq "")
	{
		$createStrorage=read-host $JsonObject.parameters.createStrorage.inputMessage		
		#$createStrorage = ($createStrorage -eq [bool]::TrueString)
		#if($createStrorage -eq $true -Or $createStrorage -eq $True)
		if(validateInput($createStrorage))		
		{
			$createStrorage = $true
			$storageAccountName=$JsonObject.parameters.storageAccountName.value
			if($storageAccountName -eq "")
			{
				$storageAccountName=read-host $JsonObject.parameters.storageAccountName.inputMessage
			}
			else { Write-Host "StorageAccountName = " $storageAccountName }
		}
		else{$createStrorage = $false}
	}else {
		Write-Host "create strorage = " $createStrorage
		$createStrorage=$JsonObject.parameters.createStrorage.value		
		#$createStrorage = ($createStrorage -eq [bool]::TrueString)
		#if($createStrorage -eq $true -Or $createStrorage -eq $True)
		if(validateInput($createStrorage))
		{
			$createStrorage = $true
			$storageAccountName=$JsonObject.parameters.storageAccountName.value
			if($storageAccountName -eq "")
			{
				$storageAccountName=read-host $JsonObject.parameters.storageAccountName.inputMessage
			}
			else { Write-Host "StorageAccountName = " $storageAccountName }
		}
		else{$createStrorage = $false}
	}

	$createWebApp=$JsonObject.parameters.createWebApp.value
	if($createWebApp -eq "")
	{
		$createWebApp=read-host $JsonObject.parameters.createWebApp.inputMessage		
		#$createWebApp = ($createWebApp -eq [bool]::TrueString)
		#if($createWebApp -eq $true -Or $createWebApp -eq $True)
		if(validateInput($createWebApp))
		{
			
			if ($createStrorage -eq $false)
			{
				Write-Host "Storage account must needed for webapp creation" -ForegroundColor Cyan
				$createStrorage = $true
				$storageAccountName=$JsonObject.parameters.storageAccountName.value
				if($storageAccountName -eq "")
				{
					$storageAccountName=read-host $JsonObject.parameters.storageAccountName.inputMessage
				}
			}
			$createWebApp = $true
			$baseName=$JsonObject.parameters.baseName.value
			if($baseName -eq "")
			{
				$baseName=read-host $JsonObject.parameters.baseName.inputMessage
			}
			else { Write-Host "App Name = " $baseName }

			$localAppDirectory=$JsonObject.parameters.localAppDirectory.value
			if($localAppDirectory -eq "")
			{
				$localAppDirectory=read-host $JsonObject.parameters.localAppDirectory.inputMessage
			}
			else { Write-Host "localAppDirectory = " $localAppDirectory }
			$customEmails=$JsonObject.parameters.customEmails.value
			if($customEmails -eq "")
			{
				$customEmails=read-host $JsonObject.parameters.customEmails.inputMessage
			}
			else { Write-Host "customEmails = " $customEmails }
		}
		else{$createWebApp = $false}
	}
	else { 
		Write-Host "Create WebApp = " $createWebApp 
		$createWebApp=$JsonObject.parameters.createWebApp.value		
		#$createWebApp = ($createWebApp -eq [bool]::TrueString)
		#if($createWebApp -eq $true -Or $createWebApp -eq $True)
		if(validateInput($createWebApp))
		{
			$createWebApp = $true
			if ($createStrorage -eq $false)
			{
				Write-Host "Storage account needed for webapp creation" -ForegroundColor Cyan
				$createStrorage = $true
				$storageAccountName=$JsonObject.parameters.storageAccountName.value
				if($storageAccountName -eq "")
				{
					$storageAccountName=read-host $JsonObject.parameters.storageAccountName.inputMessage
				}
			}
			$baseName=$JsonObject.parameters.baseName.value
			if($baseName -eq "")
			{
				$baseName=read-host $JsonObject.parameters.baseName.inputMessage
			}
			else { Write-Host "App Name = " $baseName }
			$localAppDirectory=$JsonObject.parameters.localAppDirectory.value
			if($localAppDirectory -eq "")
			{
				$localAppDirectory=read-host $JsonObject.parameters.localAppDirectory.inputMessage
			}
			else { Write-Host "localAppDirectory = " $localAppDirectory }
			$customEmails=$JsonObject.parameters.customEmails.value
			if($customEmails -eq "")
			{
				$customEmails=read-host $JsonObject.parameters.customEmails.inputMessage
			}
			else { Write-Host "customEmails = " $customEmails }
		}
		else{$createWebApp = $false}
	}
	

	$createAKeyVault=$JsonObject.parameters.createAKeyVault.value
	if($createAKeyVault -eq "")
	{
		$createAKeyVault=read-host $JsonObject.parameters.createAKeyVault.inputMessage		
		#$createAKeyVault = ($createAKeyVault -eq [bool]::TrueString)
		#if($createAKeyVault -eq $true -Or $createAKeyVault -eq $True)
		if(validateInput($createAKeyVault))
		{
			$createAKeyVault = $true
			$keyVaultName=$JsonObject.parameters.keyVaultName.value
			if($keyVaultName -eq "")
			{
				$keyVaultName=read-host $JsonObject.parameters.keyVaultName.inputMessage
			}
		}
		else{$createAKeyVault = $false}
	}	
	else {
		Write-Host "keyVaultName = " $keyVaultName
		$createAKeyVault=$JsonObject.parameters.createAKeyVault.value		
		#$createAKeyVault = ($createAKeyVault -eq [bool]::TrueString)
		#if($createAKeyVault -eq $true -Or $createAKeyVault -eq $True)
		if(validateInput($createAKeyVault))
		{
			$createAKeyVault = $true
			$keyVaultName=$JsonObject.parameters.keyVaultName.value
			if($keyVaultName -eq "")
			{
				$keyVaultName=read-host $JsonObject.parameters.keyVaultName.inputMessage
			}
		}
		else{$createAKeyVault = $false}
	}
	$createAzureADApp=$JsonObject.parameters.createAzureADApp.value
	if($createAzureADApp -eq "")
	{
		$createAzureADApp=read-host $JsonObject.parameters.createAzureADApp.inputMessage		
		#$createAzureADApp = ($createAzureADApp -eq [bool]::TrueString)
		#if($createAzureADApp -eq $true -Or $createAzureADApp -eq $True)
		if(validateInput($createAzureADApp))
		{
			$createAzureADApp = $true
			$aadAppName=$JsonObject.parameters.aadAppName.value
			if($aadAppName -eq "")
			{
				$aadAppName=read-host $JsonObject.parameters.aadAppName.inputMessage
			}
		}
		else{$createAzureADApp = $false}
	}	
	else { 
		Write-Host "create aadApp = " $createAzureADApp 
		$createAzureADApp=$JsonObject.parameters.createAzureADApp.value		
		#$createAzureADApp = ($createAzureADApp -eq [bool]::TrueString)
		#if($createAzureADApp -eq $true -Or $createAzureADApp -eq $True)
		if(validateInput($createAzureADApp))
		{
			$createAzureADApp = $true
			$aadAppName=$JsonObject.parameters.aadAppName.value
			if($aadAppName -eq "")
			{
				$aadAppName=read-host $JsonObject.parameters.aadAppName.inputMessage
			}
		}
		else{$createAzureADApp = $false}
	}	
	$createAppGw=$JsonObject.parameters.createAppGw.value
	if($createAppGw -eq "")
	{
		$createAppGw=read-host $JsonObject.parameters.createAppGw.inputMessage
		#$createAppGw = ($createAppGw -eq [bool]::TrueString)
		#if($createAppGw -eq $true -Or $createAppGw -eq $True)
		if(validateInput($createAppGw))
		{
			$createAppGw = $true
			$pfxFile= $JsonObject.parameters.pfxFile.value
			if($pfxFile -eq "")
			{
				$pfxFile=read-host $JsonObject.parameters.pfxFile.inputMessage '(ex.,c:\cert\prod_onakumina_com.pfx)'
			}
			else { Write-Host "PfxFile = " $pfxFile }
			$backendHostName= $JsonObject.parameters.backendHostName.value
			if($backendHostName -eq "")
			{
				$backendHostName=read-host $JsonObject.parameters.backendHostName.inputMessage 
			}
			else { Write-Host "BackendHostName = " $backendHostName }
			$vnetAddressPrefix= $JsonObject.parameters.vnetAddressPrefix.value
			if($vnetAddressPrefix -eq "")
			{
				$vnetAddressPrefix=read-host $JsonObject.parameters.vnetAddressPrefix.inputMessage
			}
			else { Write-Host "PfxFile = " $vnetAddressPrefix }
			$subnetPrefix= $JsonObject.parameters.subnetPrefix.value
			if($subnetPrefix -eq "")
			{
				$subnetPrefix=read-host $JsonObject.parameters.subnetPrefix.inputMessage
			}
			else { Write-Host "PfxFile = " $subnetPrefix }
		}
		else{$createAppGw = $false}
	}
	else
	{
		Write-Host "createAppGw = " $createAppGw
		#$createAppGw = ($createAppGw -eq [bool]::TrueString)
		#if($createAppGw -eq $true -Or $createAppGw -eq $True)
		if(validateInput($createAppGw))
		{
			$createAppGw = $true
			$pfxFile= $JsonObject.parameters.pfxFile.value
			if($pfxFile -eq "")
			{
				$pfxFile=read-host $JsonObject.parameters.pfxFile.inputMessage '(ex.,c:\cert\prod_onakumina_com.pfx)'
			}
			else { Write-Host "PfxFile = " $pfxFile }
			$backendHostName= $JsonObject.parameters.backendHostName.value
			if($backendHostName -eq "")
			{
				$backendHostName=read-host $JsonObject.parameters.backendHostName.inputMessage 
			}
			else { Write-Host "BackendHostName = " $backendHostName }
			$vnetAddressPrefix= $JsonObject.parameters.vnetAddressPrefix.value
			if($vnetAddressPrefix -eq "")
			{
				$vnetAddressPrefix=read-host $JsonObject.parameters.vnetAddressPrefix.inputMessage
			}
			else { Write-Host "PfxFile = " $vnetAddressPrefix }
			$subnetPrefix= $JsonObject.parameters.subnetPrefix.value
			if($subnetPrefix -eq "")
			{
				$subnetPrefix=read-host $JsonObject.parameters.subnetPrefix.inputMessage
			}
			else { Write-Host "PfxFile = " $subnetPrefix }
		}
		else{
			$createAppGw = $false
		}
		
	}
	$createRedisCache=$JsonObject.parameters.createRedisCache.value
	if($createRedisCache -eq "")
	{
		$createRedisCache=read-host $JsonObject.parameters.createRedisCache.inputMessage
		#$createRedisCache = ($createRedisCache -eq [bool]::TrueString)
		#if($createRedisCache -eq $true -Or $createRedisCache -eq $True)
		if(validateInput($createRedisCache))
		{
			$createRedisCache = $true
			$RedisCacheName=$JsonObject.parameters.RedisCacheName.value
			if($RedisCacheName -eq "")
			{
				$RedisCacheName=read-host $JsonObject.parameters.RedisCacheName.inputMessage
			}
			else { Write-Host "RedisCacheName = " $RedisCacheName }
		}
		else{$createRedisCache = $false}
	}
	else{
		Write-Host "createRedisCache = " $createRedisCache
		#$createRedisCache = ($createRedisCache -eq [bool]::TrueString)
		#if($createRedisCache -eq $true -Or $createRedisCache -eq $True)
		if(validateInput($createRedisCache))
		{
			$createRedisCache = $true
			$redisCacheName=$JsonObject.parameters.redisCacheName.value
			if($redisCacheName -eq "")
			{
				$redisCacheName=read-host $JsonObject.parameters.redisCacheName.inputMessage
			}
			else { Write-Host "RedisCacheName = " $redisCacheName }
		}
		else{$createRedisCache = $false}
	}	
	$createTrafficManager=$JsonObject.parameters.createTrafficManager.value
	if($createTrafficManager -eq "")
	{
		$createTrafficManager=read-host $JsonObject.parameters.createTrafficManager.inputMessage
		#$createTrafficManager = ($createTrafficManager -eq [bool]::TrueString)
		$createTrafficManager = validateInput($createTrafficManager)
	}	
	else { Write-Host "createTrafficManager = " $createTrafficManager }
	$createDistributionApp=$JsonObject.parameters.createDistributionApp.value
	if($createDistributionApp -eq "")
	{
		$createDistributionApp=read-host $JsonObject.parameters.createDistributionApp.inputMessage
		#$createDistributionApp = ($createDistributionApp -eq [bool]::TrueString)
		#if($createDistributionApp -eq $true -Or $createDistributionApp -eq $True)
		if(validateInput($createDistributionApp))
		{
			$createDistributionApp = $true
			$functionAppName=$JsonObject.parameters.functionAppName.value
			if($functionAppName -eq "")
			{
				$functionAppName=read-host $JsonObject.parameters.functionAppName.inputMessage
			}
			else { Write-Host "FunctionAppName = " $functionAppName }
			$akQueryKey= $JsonObject.parameters.akQueryKey.value
			if($akQueryKey -eq "")
			{
				$akQueryKey=read-host $JsonObject.parameters.akQueryKey.inputMessage
			}
			else { Write-Host "AkQueryKey = " $akQueryKey }
			$akAppManagerUrl= $JsonObject.parameters.akAppManagerUrl.value
			if($akAppManagerUrl -eq "")
			{
				$akAppManagerUrl=read-host $JsonObject.parameters.akAppManagerUrl.inputMessage
			}
			else { Write-Host "AkAppManagerUrl = " $akAppManagerUrl }
			$distributionAppDirectory=$JsonObject.parameters.distributionAppDirectory.value
			if($distributionAppDirectory -eq "")
			{
				$distributionAppDirectory=read-host $JsonObject.parameters.distributionAppDirectory.inputMessage
			}
			else { Write-Host "DistributionAppDirectory = " $distributionAppDirectory }
			$akDistributionKeyVaultUri=$JsonObject.parameters.akDistributionKeyVaultUri.value
			if($akDistributionKeyVaultUri -eq "")
			{
				$akDistributionKeyVaultUri=read-host $JsonObject.parameters.akDistributionKeyVaultUri.inputMessage
			}
			else { Write-Host "DistributionAppDirectory = " $akDistributionKeyVaultUri }
		}
		else{$createDistributionApp = $false}
	}
	else 
	{ 
		Write-Host "createDistributionApp = " $createDistributionApp 
		#$createDistributionApp = ($createDistributionApp -eq [bool]::TrueString)
		#if($createDistributionApp -eq $true -Or $createDistributionApp -eq $True)
		if(validateInput($createDistributionApp))
		{
			$createDistributionApp = $true
			$functionAppName=$JsonObject.parameters.functionAppName.value
			if($functionAppName -eq "")
			{
				$FunctionAppName=read-host $JsonObject.parameters.functionAppName.inputMessage
			}
			else { Write-Host "FunctionAppName = " $functionAppName }
			$akQueryKey= $JsonObject.parameters.akQueryKey.value
			if($AkQueryKey -eq "")
			{
				$akQueryKey=read-host $JsonObject.parameters.akQueryKey.inputMessage
			}
			else { Write-Host "AkQueryKey = " $akQueryKey }
			$akAppManagerUrl= $JsonObject.parameters.akAppManagerUrl.value
			if($AkAppManagerUrl -eq "")
			{
				$akAppManagerUrl=read-host $JsonObject.parameters.akAppManagerUrl.inputMessage
			}
			else { Write-Host "AkAppManagerUrl = " $akAppManagerUrl }
			$distributionAppDirectory=$JsonObject.parameters.distributionAppDirectory.value
			if($distributionAppDirectory -eq "")
			{
				$distributionAppDirectory=read-host $JsonObject.parameters.distributionAppDirectory.inputMessage
			}
			else { Write-Host "DistributionAppDirectory = " $distributionAppDirectory }
			$akDistributionKeyVaultUri=$JsonObject.parameters.akDistributionKeyVaultUri.value
			if($akDistributionKeyVaultUri -eq "")
			{
				$akDistributionKeyVaultUri=read-host $JsonObject.parameters.akDistributionKeyVaultUri.inputMessage
			}
			else { Write-Host "DistributionAppDirectory = " $akDistributionKeyVaultUri }
		}
		else{$createDistributionApp = $false}
	}
	if ($baseName -eq "")
	{
		$baseName = $resourceGroupName
	}
	#if ($resourceGroupName -eq "")
	ProvisionAkWebApp  -TenantId $tenantId -SubscriptionId $subscriptionId -BaseName $baseName -Location $location -ResourceGroupName $resourceGroupName -AadAppName $aadAppName -StorageAccountName $storageAccountName -KeyVaultName $keyVaultName -LocalAppDirectory $localAppDirectory -CustomEmails $customEmails -CreateAppGw $createAppGw -CreateRedisCache $createRedisCache -RedisCacheName $redisCacheName -CreateTrafficManager $createTrafficManager -PfxFile $pfxFile -BackendHostName $backendHostName -CreateDistributionApp $createDistributionApp -AkQueryKey $akQueryKey -AkAppManagerUrl $akAppManagerUrl -DistributionAppDirectory $distributionAppDirectory -FunctionAppName $functionAppName	-vnetAddressPrefix $vnetAddressPrefix -subnetPrefix $subnetPrefix -createWebApp $createWebApp -createAzureADApp $createAzureADApp -createStrorage $createStrorage -createAKeyVault $createAKeyVault -akDistributionKeyVaultUri $akDistributionKeyVaultUri
}
else
{
    Write-Host "Parameters file missing, Place the parameters.json file in app installation location"
}




