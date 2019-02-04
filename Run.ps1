#Pre-req:
# 1.	Windows Server 2016/10 Powershell version 5.1 already installed
#       Windows Server 2012R2 download Workforce Management (WFM) package from https://docs.microsoft.com/en-us/powershell/wmf/5.1/install-configure
# 2.    If this is the first time running, install the AzureRM and AzureAD modules on your local machine using the following commands
#       Install-Module -Name AzureRM -RequiredVersion 6.8.1 -Repository PSGallery
#		OR Run this command to update to required version: Update-Module -Name AzureRM -RequiredVersion 6.8.1 -Repository PSGallery
#		Can also download from https://github.com/Azure/azure-powershell/releases/tag/v6.8.1-Auust2018
#		Install-Module -Name AzureAD -RequiredVersion 2.0.1.10
# 3.	Optional: If you already installed AzureRM and AzureAD, but keep getting command not found, then the module(s) may not be loaded. You can load them manually by running the following commands
#		Import-Module -Name AzureRM
#		Import-Module -Name AzureAD
# 4.	If you get a certificate error, then you may need to change the execution policy
#		Example commands: Set-ExecutionPolicy RemoteSigned  OR Set-ExecutionPolicy Unrestricted
# 5.	To get a list of Azure server locations, log into your Azure portal, open a PowerShell and run the command Get-AzureRmLocation


#Edit the following to point to your working directory that contains the ps files
cd C:\Work\AkDev\AzureAutomation

$ErrorActionPreference = 'Stop'

$version=$PSVersionTable.PSVersion.Major
if($version -lt 5)
{
    Throw "Version is not supported, please upgrade to 5 or later"
}

import-module .\Common.psm1

#get-help  ProvisionAkWebApp

$tenantId=read-host "Enter TenantId (DirectoryId)"
$subscriptionId=read-host "Enter SubscriptionId"
$baseName=read-host "Enter App name (ex.,aksvchub01)"
$location=read-host "Enter location (ex.,eastus2), if you leave empty location will be default to eastus2"
$resourceGroupName=read-host "Enter resource group name, leave empty if you want to create a resource group as App name"
$storageAccountName=read-host "Enter StorageAccount name, leave empty if you want to create a Storage Account as App name"
$keyVaultName=read-host "Enter KeyVault name, leave empty if you want to create a key vault as App name"
$aadAppName=read-host "Enter AAD App name, leave empty if you want to create a aadApp as App name"
$localAppDirectory=read-host "Enter Local App Directory, leave empty if you want to upload the files later"
$customEmails=read-host "Enter email address to set alert notification, leave empty if you do not want to set alert notification"
$createAppGw=read-host "Provision App Gateway (True/False)"
$createAppGw = ($createAppGw -eq [bool]::TrueString)
if($createAppGw -eq $true)
{
	$PfxFile=read-host "Enter full path to pfx file to configure app gateway secure frontend(ex.,c:\cert\prod_onakumina_com.pfx)"
	$BackendHostName=read-host "Enter fqdn for the web app backend pool(ex., prod.onakumina.com)"
}
$createRedisCache=read-host "Provision Redis Cache (True/False)"
$createRedisCache = ($createRedisCache -eq [bool]::TrueString)
if($createRedisCache -eq $true)
{
	$RedisCacheName=read-host "Enter Redis Service name, leave empty if you want to create a Redis Service as App name"
}
$createTrafficManager=read-host "Provision Traffic Manager (True/False)"
$createTrafficManager = ($createTrafficManager -eq [bool]::TrueString)

ProvisionAkWebApp  -TenantId $tenantId -SubscriptionId $subscriptionId -BaseName $baseName -Location $location -ResourceGroupName $resourceGroupName -AadAppName $aadAppName -StorageAccountName $storageAccountName -KeyVaultName $keyVaultName -LocalAppDirectory $localAppDirectory -CustomEmails $customEmails -CreateAppGw $createAppGw -CreateRedisCache $createRedisCache -RedisCacheName $RedisCacheName -CreateTrafficManager $createTrafficManager -PfxFile $PfxFile -BackendHostName $BackendHostName