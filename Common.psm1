class AppData {
    [string]$AppId
    [string]$AppSecret
}
class StorageData {
    [string]$ConnectionString
}
class RedisCache {
    [string]$ConnectionString
}
class FtpData {
    [string]$Host
    [string]$UserName
    [string]$Password
}

Function ProvisionAkWebApp([string]$TenantId, [string]$SubscriptionId, [string]$BaseName, [string]$Location,[string]$AadAppName = "", [string]$ResourceGroupName = "",[string]$StorageAccountName = "",[string]$KeyVaultName = "", [string[]]$ReplyUrls = "", [string]$localAppDirectory = "", [string]$CustomEmails, [bool]$CreateAppGw = $false, [bool]$CreateRedisCache = $false, [string]$RedisCacheName = "",[bool]$CreateTrafficManager = $false, [string]$BackendHostName = "", [string]$PfxFile = "",[bool]$CreateDistributionApp = $false, [string]$AkQueryKey = "", [string]$AkAppManagerUrl = "",[string]$DistributionAppDirectory,[string]$FunctionAppName, [string]$vnetAddressPrefix ,[string]$subnetPrefix , [bool]$createWebApp =$false,[bool]$createAzureADApp=$false,[bool]$createStrorage=$false,[bool]$createAKeyVault=$false, [string]$akDistributionKeyVaultUri="",[string]$akDistributionConnectionName="") {
    if ($BaseName -eq "") {
        $BaseName = $ResourceGroupName
    }
	$HomePage = "https://$BaseName.azurewebsites.net"
    $backendIpAddress1 = "$BaseName.azurewebsites.net"
    if (($ReplyUrls.Length -eq 0) -or ($ReplyUrls[0] -eq "")) {
        $ReplyUrls = "$HomePage/oauth2/acs"
    }
    if ($Location -eq "") {
        $Location = "eastus2"
    }
    $appName = $BaseName
    
    if ($StorageAccountName -eq "") {
        $StorageAccountName = $appName
    }
    if ($ResourceGroupName -eq "") {
        $ResourceGroupName = $appName
    }
    if ($KeyVaultName -eq "") {
        $KeyVaultName = $appname
    }
    if ($AadAppName -eq "") {
        $AadAppName = "ad-$appName"
    }
	if ($FunctionAppName -eq "") {
        $FunctionAppName = "fn-$appName"
    }
    if ($RedisCacheName -eq "") {
        $RedisCacheName = $appName
    }
    if ($PfxFile -and $CreateAppGw) {
        $SecurePassword = Read-Host -Prompt "Enter Pfx password" -AsSecureString
    }
	#if($akDistributionKeyVaultUri -eq "")
	#{
	#	$createStrorage = $true	
	#}
    
    Login-AzureRmAccount -TenantId $TenantId 
    $credentials = Connect-AzureAD -TenantId $TenantId
    $user = Get-AzureRmADUser -UserPrincipalName $credentials.Account.Id
    $appData=Get-AzureRmADApplication -DisplayNameStartWith $AadAppName -ErrorVariable aadAppNotExists -ErrorAction SilentlyContinue
	if($createAzureADApp)
	{
		if ($null -eq $appData) {
			Write-Host "Provisioning Aad App started..." -ForegroundColor Cyan
			$appData = RegisterADApp -AppName $AadAppName -Uri $HomePage -ReplyUrls $ReplyUrls
			Write-Host "Provisioning Aad App ended..." -ForegroundColor Cyan
		}
		else {
			Write-Host "Provisioning Aad App skipped..." -ForegroundColor Cyan
		}
	}
	else {
			Write-Host "Provisioning Aad App skipped..." -ForegroundColor Cyan
	}
    Set-AzureRmContext -SubscriptionId $SubscriptionId 
    Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorVariable rgNotExists -ErrorAction SilentlyContinue
    if ($rgNotExists) {
        Write-Host "Provisioning Resource Group started..." -ForegroundColor Cyan
        CreateResourceGroup -ResourceGroupName $ResourceGroupName -Location $Location
        Write-Host "Provisioning Resource Group ended..." -ForegroundColor Cyan
    }
    else {
        Write-Host "Provisioning Resource Group skipped..." -ForegroundColor Cyan
    }
	if($createStrorage)
	{
		$storage = CreateStorageAccount -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Location $Location -contentdistribution $false
		$ctx = $storage.Context
	}
	else {
        Write-Host "Storage creation skipped..." -ForegroundColor Cyan
    }
	if($createWebApp)
	{
		$wp = Get-AzureRmWebApp -Name $appName
		if ($null -eq $wp) {
			Write-Host "Provisioning webapp started..." -ForegroundColor Cyan
			New-AzureRmResourceGroupDeployment -Name $appName -TemplateFile akwebapp.json -ResourceGroupName $ResourceGroupName -baseResourceName $appName
			Write-Host "Provisioning webapp ended..." -ForegroundColor Cyan
		}
		else {
			Write-Host "Provisioning webapp skipped..." -ForegroundColor Cyan
		}
	}
	else {
        Write-Host "Provisioning webapp skipped..." -ForegroundColor Cyan
    }     
	if($createAKeyVault)
	{
		$servicePrincipals = $null
		$iteration = 0
		while ($iteration -le 12) {
			$servicePrincipals = get-azurermadserviceprincipal -SearchString $appName
			if ($null -ne $servicePrincipals) {
				break
			}
			Start-Sleep -s 5
			$iteration++
		}
		$objectId = $servicePrincipals[0].Id
		$secretName = "StorageConnectionString"
		$secretvalue = ConvertTo-SecureString –String $storage.ConnectionString –AsPlainText –Force 
		$kv = Get-AzureRmKeyVault -VaultName $KeyVaultName
		if ($null -eq $kv) {
			Write-Host "Provisioning Keyvault started..." -ForegroundColor Cyan
			New-AzureRmResourceGroupDeployment -Name AkWebAppKeyVault -tenantId $TenantId -keyVaultName $KeyVaultName -objectId $objectId -secretName $secretName -secretValue $secretValue -TemplateFile akkeyvault.json -ResourceGroupName $ResourceGroupName -userId  $user.Id.Guid.ToString()
			Write-Host "Provisioning Keyvault ended..." -ForegroundColor Cyan
		}
		else {
			Write-Host "Provisioning Keyvault skipped..." -ForegroundColor Cyan
		}
		$secretIdUri = Get-AzureKeyVaultSecret -VaultName  $KeyVaultName -Name $secretName
	}
	else {
		Write-Host "Provisioning Keyvault skipped..." -ForegroundColor Cyan
	}
    
	
	
    if ($CreateRedisCache) {
        #Create Redis
        Get-AzureRmRedisCache -Name $RedisCacheName -ErrorVariable rcNotExists -ErrorAction SilentlyContinue
        if ($rcNotExists) {
            Write-Host "Provisioning Redis cache started..." -ForegroundColor Cyan
            New-AzureRmResourceGroupDeployment -TemplateFile akredis.json -ResourceGroupName $ResourceGroupName -RedisName $RedisCacheName 
            $cacheKeys = Get-AzureRmRedisCacheKey -ResourceGroupName $ResourceGroupName -Name $RedisCacheName
            $primaryCacheKey = $cacheKeys.PrimaryKey
            $cacheKeyData = New-Object RedisCache
            $cacheKeyData.ConnectionString = "$RedisCacheName.redis.cache.windows.net:6380,password=$primaryCacheKey,ssl=True,abortConnect=False" 
            Write-Host "Provisioning Redis cache ended..." -ForegroundColor Cyan
        }
        else {
            Write-Host "Provisioning Redis cache skipped..." -ForegroundColor Cyan
        }
    }
	
    if ($CreateAppGw) {		
        #AppGateway
        $appGw = "$appName-appgw"
        Get-AzureRmApplicationGateway -Name $appGw -ResourceGroupName $ResourceGroupName  -ErrorVariable agNotExists -ErrorAction SilentlyContinue
        if ($agNotExists) {
            Write-Host "Provisioning App Gateway started..." -ForegroundColor Cyan
            $sslCertificate = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($PfxFile))
            #$cerFile= $PfxFile -replace '.pfx','.cer'
            #$SslPublicCertificate=[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($cerFile))
            #New-AzureRmResourceGroupDeployment -TemplateFile testgateway.json -ResourceGroupName $ResourceGroupName -applicationGatewayName $appName -sslCertificate $sslCertificate -certPassword $securePassword -hostName $backendHostName -vnetAddressPrefix $vnetAddressPrefix -subnetPrefix $subnetPrefix
			if($vnetAddressPrefix -eq "")
			{
				$vnetAddressPrefix = "10.10.0.0/16"
			}
			if($subnetPrefix -eq "")
			{
				$subnetPrefix = "10.10.0.0/24"
			}
			$webApps = Get-AzureRmWebApp -Name $appName -ResourceGroupName $ResourceGroupName
			if ($null -eq $webApps)
			{
				$backendHostName = '$appName.onakumina.com'
			}
			else
			{
				$backendHostName = $webApps.DefaultHostName.ToString()				
			}
			#if ($backendHostName -eq "")
			#{
				#$backendHostName = '$appName.onakumina.com'
			#}
			New-AzureRmResourceGroupDeployment -TemplateFile akappgateway.json -ResourceGroupName $ResourceGroupName -applicationGatewaysName $appName -sslCertificate $sslCertificate -certPassword $securePassword -hostName $backendHostName -backendIPAddresses $backendHostName -vnetAddressPrefix $vnetAddressPrefix -subnetPrefix $subnetPrefix
						
            Write-Host "Provisioning App Gateway ended..." -ForegroundColor Cyan
        }
        else {
            Write-Host "Provisioning App Gateway skipped..." -ForegroundColor Cyan
        }		
    }
	
    if ($CreateTrafficManager -and $CreateAppGw) {

        #Create Traffic Manager
        Get-AzureRmTrafficManagerEndpoint -ProfileName $appname -Name $BackendHostName -ResourceGroupName $ResourceGroupName -Type ExternalEndpoints -ErrorVariable tmpNotExists -ErrorAction SilentlyContinue
        if ($tmpNotExists) {
            Write-Host "Provisioning Traffic manager profile started..." -ForegroundColor Cyan
            New-AzureRmResourceGroupDeployment -TemplateFile aktrafficmanager.json -ResourceGroupName $ResourceGroupName -TrafficManagerProfilesName $appname -HostName $BackendHostName 
            $tmpEp = Get-AzureRmTrafficManagerEndpoint -Name $BackendHostName -Type AzureEndpoints -ProfileName $appname -ResourceGroupName $ResourceGroupName
            Add-AzureRmTrafficManagerCustomHeaderToEndpoint -TrafficManagerEndpoint $tmpEp -Name "host" -Value $BackendHostName
            Set-AzureRmTrafficManagerEndpoint -TrafficManagerEndpoint $tmpEp
            Write-Host "Provisioning Traffic manager profile ended..." -ForegroundColor Cyan
        }
        else {
            Write-Host "Provisioning Traffic manager profile skipped..." -ForegroundColor Cyan
        }
    }
    $backgroundGuid = [guid]::NewGuid().ToString()
	if ($CreateDistributionApp) 
	{
		$wp = Get-AzureRmWebApp -Name $FunctionAppName
		if ($null -eq $wp) {
			Write-Host "Provisioning content distribution app started..." -ForegroundColor Cyan
			if($AkAppManagerUrl -eq "")
			{
				$AkAppManagerUrl="$appName.azurewebsites.net"	
			}
			if($AkQueryKey -eq "")
			{
				$AkQueryKey=$backgroundGuid	
			}
			#$appInsightLocation = $Location -replace "[^a-zA-Z]" , ''
			$appInsightLocation = $Location
			New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -appName $FunctionAppName -TemplateFile akfunapp.json -location $appInsightLocation
			Write-Host "Provisioning content distribution app ended..." -ForegroundColor Cyan
			if(($akDistributionConnectionName -eq ""))
			{
				$akDistributionConnectionKeyName = "AzureWebJobsStorage"
			}
			else {$akDistributionConnectionKeyName = $akDistributionConnectionName}

			if($StorageAccountName  -eq $ResourceGroupName)
			{
				$storage = CreateStorageAccount -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Location $Location -contentdistribution $true
				$ctx = $storage.Context
			}
			else
			{
				$storage = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
				$ctx = $storage.Context
			}
			if ($akDistributionKeyVaultUri -eq "")
			{					
				if($StorageAccountName -eq $ResourceGroupName)
				{
					$storage = CreateStorageAccount -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Location $Location -contentdistribution $true
					$ctx = $storage.Context
				}
				else
				{
					$storage = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
					$ctx = $storage.Context
				}
				#$KeyVaultName = $appname
				if($keyVaultName -eq $ResourceGroupName)
				{		
					$servicePrincipals = $null
					$iteration = 0
					while ($iteration -le 12) {
						$servicePrincipals = get-azurermadserviceprincipal -SearchString $FunctionAppName
						if ($null -ne $servicePrincipals) {
							break
						}
						Start-Sleep -s 5
						$iteration++
					}
					$objectId = $servicePrincipals[0].Id
					$secretName = "StorageConnectionString"
					$secretvalue = ConvertTo-SecureString –String $storage.ConnectionString –AsPlainText –Force 
					$kv = Get-AzureRmKeyVault -VaultName $KeyVaultName
					if ($null -eq $kv) {
						#Write-Host "Provisioning Keyvault started..." -ForegroundColor Cyan
						New-AzureRmResourceGroupDeployment -Name AkWebAppKeyVault -tenantId $TenantId -keyVaultName $KeyVaultName -objectId $objectId -secretName $secretName -secretValue $secretValue -TemplateFile akkeyvault.json -ResourceGroupName $ResourceGroupName -userId  $user.Id.Guid.ToString()
						#Write-Host "Provisioning Keyvault ended..." -ForegroundColor Cyan
					}
					$secretIdUri = Get-AzureKeyVaultSecret -VaultName  $KeyVaultName -Name $secretName
					$akDistributionConnKeyVaultUri = $secretIdUri.Id
					$akDistributionConnectionKeyValue ="@Microsoft.KeyVault(SecretUri=$akDistributionConnKeyVaultUri)"
				}
				else{				
					$kv = Get-AzureRmKeyVault -VaultName $KeyVaultName
					if ($null -eq $kv) {
						#Write-Host "Provisioning Keyvault started..." -ForegroundColor Cyan
						New-AzureRmResourceGroupDeployment -Name AkWebAppKeyVault -tenantId $TenantId -keyVaultName $KeyVaultName -objectId $objectId -secretName $secretName -secretValue $secretValue -TemplateFile akkeyvault.json -ResourceGroupName $ResourceGroupName -userId  $user.Id.Guid.ToString()
						#Write-Host "Provisioning Keyvault ended..." -ForegroundColor Cyan
					}
					$secretIdUri = Get-AzureKeyVaultSecret -VaultName  $KeyVaultName -Name $secretName
					$akDistributionConnKeyVaultUri = $secretIdUri.Id
					$akDistributionConnectionKeyValue ="@Microsoft.KeyVault(SecretUri=$akDistributionConnKeyVaultUri)"
				}
			}
			else
			{
				$akDistributionConnectionKeyValue ="@Microsoft.KeyVault(SecretUri=$akDistributionConnKeyVaultUri)"
			}
			
			Set-AzureRmWebApp -AssignIdentity $true -Name $FunctionAppName -ResourceGroupName $ResourceGroupName
			$newGuid = [guid]::newguid()
			$tempFolder = $env:temp
			$extractLocation = "$tempFolder\Akumina"
			if((Test-Path -Path $extractLocation))
			{
				Remove-Item  -Recurse -Force -Path $extractLocation
				New-Item -Path $extractLocation -ItemType directory
				$extractLocation = "$extractLocation\$newGuid"
				New-Item -Path $extractLocation\ -ItemType directory
			}
			else{
				New-Item -Path $extractLocation -ItemType directory
				$extractLocation = "$extractLocation\$newGuid"
				New-Item -Path $extractLocation\ -ItemType directory
			}
			$DownloadToFolder = $extractLocation
			$cdFile = "contentdistributionv0.1.zip"
			$downloadurl ="https://akumina.azureedge.net/interchange/contentdistribution/contentdistributionv0.1.zip"			
			$fileFolder = DownloadContentDistributionFiles -DownloadToFolder $DownloadToFolder -downloadurl $downloadurl -cdFile $cdFile
			$DistributionAppDirectory = $DownloadToFolder
			$replaceText = """connection"":""$akDistributionConnectionKeyName"""
			(Get-Content $DistributionAppDirectory\ContentDistributionQueueProcessor\function.json ).Replace('"connection": "AzureWebJobsStorage"',$replaceText) | Out-File $DistributionAppDirectory\ContentDistributionQueueProcessor\function.json
			$replaceText = """connection"":""$akDistributionQueneName"""
			(Get-Content $DistributionAppDirectory\ContentDistributionQueueProcessor\function.json ).Replace('"queueName": "ws2019queue"',$replaceText) | Out-File $DistributionAppDirectory\ContentDistributionQueueProcessor\function.json
			$DistributionAppFtp = UpdateFunctionApp -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WebAppName $FunctionAppName -Location $Location -AppDirectory $DistributionAppDirectory -CustomEmails $CustomEmails -AkQueryKey $AkQueryKey -AkAppManagerUrl $AkAppManagerUrl -FunctionAppName $FunctionAppName -AkDistributionKeyVaultUri $akDistributionKeyVaultUri -StorageAccountName $StorageAccountName -akDistributionConnectionKeyName $akDistributionConnectionKeyName -akDistributionConnectionKeyValue $akDistributionConnectionKeyValue			
			
		}
		else{
			Write-Host "Provisioning content distribution app skipped..." -ForegroundColor Cyan
		}
    }
	else{
			Write-Host "Provisioning content distribution app skipped..." -ForegroundColor Cyan
	}

    if ($localAppDirectory -ne "") {
        ReplaceInterchangeSetting -configFilePath "$localAppDirectory\interchange.settings.config" -key "akumina:RemoteStorageConnection" -newValue $secretIdUri.Id
        ReplaceInterchangeSetting -configFilePath "$localAppDirectory\interchange.settings.config" -key "akumina:BackgroundProcessorKey" -newValue $backgroundGuid
        ReplaceInterchangeSetting -configFilePath "$localAppDirectory\interchange.settings.config" -key "akumina:LogListener" -newValue "AzureTable"
        if ($CreateRedisCache) {
            ReplaceInterchangeSetting -configFilePath "$localAppDirectory\interchange.settings.config" -key "akumina:PrimaryRedisConnection" -newValue $cacheKeyData.ConnectionString
            UpdateUnityCachingToRedis -configFilePath "$localAppDirectory\unity.config" 
        }
    }
		if($createWebApp)
		{
			$ftp = UpdateWebApp -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WebAppName $appName -Location $Location -AppDirectory $localAppDirectory -CustomEmails $CustomEmails
			
		}
		
		Write-Host "AD App Name: $AadAppName" -ForegroundColor Cyan
		Write-Host "AD App ID: "($appData.AppId) -ForegroundColor Cyan
		Write-Host "AD App Secret: "($appData.AppSecret) -ForegroundColor Cyan
		Write-Host "Storage ConnectionString: "($storage.ConnectionString) -ForegroundColor Cyan
		Write-Host "Secret Id Uri: "($secretIdUri.Id) -ForegroundColor Cyan
		Write-Host "Redis Connection String: "($cacheKeyData.ConnectionString) -ForegroundColor Cyan
		Write-Host "AzureWebSite Url: $HomePage" -ForegroundColor Cyan		
		Write-Host "BackgroundProcessorKey: $backgroundGuid" -ForegroundColor Cyan
		if($createWebApp)
		{			
			Write-Host "FTP Host: "($ftp.Host) -ForegroundColor Cyan
			Write-Host "FTP User: "($ftp.UserName) -ForegroundColor Cyan
			Write-Host "FTP Password: "($ftp.Password) -ForegroundColor Cyan
		}
		elseif($DistributionAppFtp -ne "")
		{
			Write-Host "FTP Host: "($DistributionAppFtp.Host) -ForegroundColor Cyan
			Write-Host "FTP User: "($DistributionAppFtp.UserName) -ForegroundColor Cyan
			Write-Host "FTP Password: "($DistributionAppFtp.Password) -ForegroundColor Cyan
		}


		Write-Host "DONE!" -ForegroundColor Green
	
}

Function ComputePassword {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    $aesManaged.GenerateKey()
    return [System.Convert]::ToBase64String($aesManaged.Key)
}

# Adds the requiredAccesses (expressed as a pipe separated string) to the requiredAccess structure
# The exposed permissions are in the $exposedPermissions collection, and the type of permission (Scope | Role) is 
# described in $permissionType
Function AddResourcePermission($requiredAccess, $exposedPermissions, [string]$requiredAccesses, [string]$permissionType) {
    foreach ($permission in $requiredAccesses.Trim().Split("|")) {
        foreach ($exposedPermission in $exposedPermissions) {
            if ($exposedPermission.Value -eq $permission) {
                $resourceAccess = New-Object Microsoft.Open.AzureAD.Model.ResourceAccess
                $resourceAccess.Type = $permissionType # Scope = Delegated permissions | Role = Application permissions
                $resourceAccess.Id = $exposedPermission.Id # Read directory data
                $requiredAccess.ResourceAccess.Add($resourceAccess)
            }
        }
    }
}

Function ReadAllAppPermission {
    [OutputType([string])]
    param([string]$AdAppId)
    $sp = Get-AzureADServicePrincipal -Filter "AppId eq '$AdAppId'"
    $perms = ""
    foreach ($s in $sp.AppRoles) {
        if ($perms -eq "") {
            $perms = $s.Value
        }
        else {
            $perms = $perms + "|" + $s.Value
        }
    }
    return $perms;
}

Function ReadAllDeligatedPermission {
    [OutputType([string])]
    param([string]$AdAppId)
    $sp = Get-AzureADServicePrincipal -Filter "AppId eq '$AdAppId'"
    $perms = ""
    foreach ($s in $sp.Oauth2Permissions) {
        if ($perms -eq "") {
            $perms = $s.Value
        }
        else {
            $perms = $perms + "|" + $s.Value
        }
    }
    return $perms;
}

# Exemple: GetRequiredPermissions "Microsoft Graph"  "Graph.Read|User.Read"
Function GetRequiredPermissions([string] $appId, [string] $requiredDelegatedPermissions, [string]$requiredApplicationPermissions) {
    $sp = Get-AzureADServicePrincipal -Filter "AppId eq '$appId'"
    $requiredAccess = New-Object Microsoft.Open.AzureAD.Model.RequiredResourceAccess
    $requiredAccess.ResourceAppId = $appid 
    $requiredAccess.ResourceAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]

    # $sp.Oauth2Permissions | Select Id,AdminConsentDisplayName,Value: To see the list of all the Delegated permissions for the application:
    if ($requiredDelegatedPermissions) {
        AddResourcePermission $requiredAccess -exposedPermissions $sp.Oauth2Permissions -requiredAccesses $requiredDelegatedPermissions -permissionType "Scope"
    }
    
    # $sp.AppRoles | Select Id,AdminConsentDisplayName,Value: To see the list of all the Application permissions for the application
    if ($requiredApplicationPermissions) {
        AddResourcePermission $requiredAccess -exposedPermissions $sp.AppRoles -requiredAccesses $requiredApplicationPermissions -permissionType "Role"
    }
    return $requiredAccess
}  

Function RegisterADApp ([string]$AppName, [string]$Uri = "https://localhost:44305", [string[]]$ReplyUrls = @("https://localhost:44305")) {
    #ObjectId                             AppId                                DisplayName
    #d89f3c59-37de-453b-b95f-18d313631b39 00000003-0000-0000-c000-000000000000 Microsoft Graph
    #f18ff2fd-ccff-4135-9ba4-11c8e8bca5bb 00000002-0000-0000-c000-000000000000 Windows Azure Active Directory
    #4c50a7fa-08bd-45ab-aefc-e93fe865bc9d 00000003-0000-0ff1-ce00-000000000000 Microsoft.SharePoint
    #21db81ce-bd4c-4b4e-bda9-2efb9dbb5147 00000004-0000-0ff1-ce00-000000000000 Microsoft.Lync
    $requiredResourcesAccess = New-Object "System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]"
    $appId = "00000003-0000-0000-c000-000000000000"
    #$appPermissions=ReadAllAppPermission($appId)
    #$deligatedPermission=ReadAllDeligatedPermission($appId)
    $appPermissions = "Sites.ReadWrite.All|Sites.Read.All|Group.Read.All|Group.ReadWrite.All|Directory.Read.All|User.Read.All|Calendars.Read"
    $deligatedPermission = "User.ReadBasic.All|User.Read.All|Group.Read.All|Group.ReadWrite.All|Directory.Read.All|Directory.AccessAsUser.All|Calendars.Read|Sites.Read.All|Tasks.Read|MailboxSettings.ReadWrite"
    $microsoftGraphRequiredPermissions = GetRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
    $requiredResourcesAccess.Add($microsoftGraphRequiredPermissions)  

    $appId = "00000002-0000-0000-c000-000000000000"
    $appPermissions = "Directory.Read.All"
    $deligatedPermission = "User.Read"
    $wadRequiredPermissions = GetRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
    $requiredResourcesAccess.Add($wadRequiredPermissions)  
    
    $appId = "00000003-0000-0ff1-ce00-000000000000"
    $appPermissions = "User.Read.All|User.ReadWrite.All|TermStore.ReadWrite.All|TermStore.Read.All|Sites.Manage.All|Sites.FullControl.All|Sites.Read.All|Sites.ReadWrite.All"
    $deligatedPermission = "User.Read.All|User.ReadWrite.All|MyFiles.Write|MyFiles.Read|AllSites.FullControl|AllSites.Manage|AllSites.Write|AllSites.Read|Sites.Search.All|TermStore.ReadWrite.All|TermStore.Read.All"     
    $microsoftSpRequiredPermissions = GetRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
    $requiredResourcesAccess.Add($microsoftSpRequiredPermissions)  
    
    $appId = "00000004-0000-0ff1-ce00-000000000000"
    $appPermissions = "Conversations.Chat"
    $deligatedPermission = "User.ReadWrite|Contacts.ReadWrite"     
    $lyncRequiredPermissions = GetRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
    $requiredResourcesAccess.Add($lyncRequiredPermissions)  
    
    $identifierUris = $uri + "/" + [GUID]::NewGuid().ToString()

    # Create the Azure AD app
    $aadApplication = New-AzureADApplication -DisplayName $AppName `
        -Homepage $Uri `
        -ReplyUrls $ReplyUrls `
        -IdentifierUris $identifierUris `
        -RequiredResourceAccess $requiredResourcesAccess `
        -Oauth2AllowImplicitFlow $true `
        -Oauth2AllowUrlPathMatching $true

    $pwdKeyValue = ComputePassword
    $startDate = Get-Date
    $endDate = $startDate.AddYears(100) 
    New-AzureADApplicationPasswordCredential -ObjectId $aadApplication.ObjectId -CustomKeyIdentifier "ak-appkey"  -Value $pwdKeyValue -StartDate $startDate -EndDate $endDate 
    $aadServicePrincipal = New-AzureADServicePrincipal -AppId $aadApplication.AppId 
    #Update service principal
    $appData = New-Object AppData
    $appData.AppId = $aadApplication.AppId
    $appData.AppSecret = $pwdKeyValue
    return $appData
}

#ReplaceSetting -configFilePath $configFilePath -key "akumina:RemoteStorageConnection" -newValue $storageConnectionString
Function ReplaceInterchangeSetting([string] $configFilePath, [string] $key, [string] $newValue) {
    $content = Get-Content $configFilePath | Out-String
    [xml] $xmlContent = $content
    $appSettings = $xmlContent.appSettings; 
    $keyValuePair = $appSettings.SelectSingleNode("descendant::add[@key='$key']")
    if ($keyValuePair) {
        $keyValuePair.value = $newValue;
    }
    else {
        Throw "Key '$key' not found in file '$configFilePath'"
    }
    $xmlContent.save($configFilePath)
}
Function UpdateUnityCachingToRedis([string] $configFilePath) {
    $content = Get-Content $configFilePath | Out-String
    [xml] $xmlContent = $content
    $target = (($xmlContent.unity.container|Where-Object {$_.name -eq "caching"}).register|where {$_.type -eq "ICachingService"})
    $target.mapTo = "RedisCachingService"
    $xmlContent.save($configFilePath)
}
Function ReplaceAppSetting([string] $configFilePath, [string] $key, [string] $newValue) {
    [xml] $content = Get-Content $configFilePath
    $appSettings = $content.configuration.appSettings; 
    $keyValuePair = $appSettings.SelectSingleNode("descendant::add[@key='$key']")
    if ($keyValuePair) {
        $keyValuePair.value = $newValue;
    }
    else {
        Throw "Key '$key' not found in file '$configFilePath'"
    }
    $content.save($configFilePath)
}

Function CreateResourceGroup([string]$ResourceGroupName, [string]$Location) {
    New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location 
}

Function CreateStorageAccount {
    [OutputType([StorageData])]
    param([string]$SubscriptionId, [string]$ResourceGroupName, [string]$StorageAccountName, [string]$Location, $SkuName = "Standard_LRS",[bool]$contentdistribution)
    $st = Get-AzureRmStorageAccountNameAvailability -Name $StorageAccountName
    if ($st.NameAvailable) {
        Write-Host "Provisioning storage account started..." -ForegroundColor Cyan
        $storageAccount = New-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Location $Location -SkuName $SkuName
        Write-Host "Provisioning storage account ended..." -ForegroundColor Cyan
    }
    else {
		if($contentdistribution -eq $false)
		{
			Write-Host "Provisioning storage account skipped..." -ForegroundColor Cyan
		}
    }
    # Retrieve the context. 
    #$ctx = $storageAccount.Context
    $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Value[0]
    $result = New-Object StorageData
    $result.ConnectionString = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$storageAccountKey" 
    return $result
    #New-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName key1 
}

Function UpdateWebApp {
    [OutputType([FtpData])]
    param([string]$SubscriptionId, [string]$ResourceGroupName, [string]$WebAppName, [string]$Location, [string]$AppDirectory, [string]$CustomEmails = "")

    # Get publishing profile for the web app
    [xml] $xml = (Get-AzureRmWebAppPublishingProfile -Name $WebAppName -ResourceGroupName $ResourceGroupName -OutputFile null)

    # Extract connection information from publishing profile
    $username = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@userName").value
    $password = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@userPWD").value
    $url = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@publishUrl").value

    #AppSettings and 32Bit Processor
    $webApp = Get-AzureRMWebApp -ResourceGroupName $ResourceGroupName -Name $WebAppName 
    $appSettings = $webApp.SiteConfig.AppSettings
    $hash = @{}
    ForEach ($kvp in $appSettings) {
        $hash[$kvp.Name] = $kvp.Value
    }
    $hash['SCM_COMMAND_IDLE_TIMEOUT'] = "3600"
    
    Set-AzureRmWebApp -Name $appName -ResourceGroupName $resourceGroupName -Use32BitWorkerProcess $false -AppSettings $hash

    #AlwaysOn
    $WebAppResourceType = 'microsoft.web/sites'
    
    $WebAppProperties = @{"siteConfig" = @{"AlwaysOn" = $true}}
    #$webAppResource = Get-AzureRmResource -ResourceType $WebAppResourceType -ResourceGroupName $ResourceGroupName
    $ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"
    Set-AzureRmResource -ResourceId $ResourceId -PropertyObject $WebAppProperties -Force
	    
    AddWebAppAlert -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -WebAppName $appName -Location $location -CustomEmails $CustomEmails
	
    # Upload files recursively 
    if ($appdirectory -ne "") {
        UploadFilesUsingFtp -appdirectory $appdirectory -username $username -password $password
    }
    $result = New-Object FtpData
    $result.Host = $url 
    $result.UserName = $username
    $result.Password = $password
    return $result
}

Function UpdateFunctionApp {
    [OutputType([FtpData])]
    param([string]$SubscriptionId, [string]$ResourceGroupName, [string]$WebAppName, [string]$Location, [string]$AppDirectory, [string]$CustomEmails = "",[string]$AkQueryKey,[string]$AkAppManagerUrl,[string]$FunctionAppName,[string]$AkDistributionKeyVaultUri,[string]$StorageAccountName,[string]$akDistributionConnectionKeyName ,[string]$akDistributionConnectionKeyValue)

    # Get publishing profile for the web app
    [xml] $xml = (Get-AzureRmWebAppPublishingProfile -Name $WebAppName -ResourceGroupName $ResourceGroupName -OutputFile null)

    # Extract connection information from publishing profile
    $username = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@userName").value
    $password = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@userPWD").value
    $url = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@publishUrl").value

    #AppSettings and 32Bit Processor
    $webApp = Get-AzureRMWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName 
    $appSettings = $webApp.SiteConfig.AppSettings
    $hash = @{}
    $hash['AkQueryKey'] = $AkQueryKey
	$hash['AkAppManagerUrl'] = $AkAppManagerUrl
    $hash['SCM_COMMAND_IDLE_TIMEOUT'] = "3600"
	$hash['AkDistributionKeyVaultUri'] = $AkDistributionKeyVaultUri
	$appInsight = Get-AzureRmApplicationInsights -ResourceGroupName $ResourceGroupName -Name $FunctionAppName 
	$hash['APPINSIGHTS_INSTRUMENTATIONKEY'] = $appInsight.InstrumentationKey.ToString()
	$storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Value[0]
    $storageConnectionString = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$storageAccountKey"

	#$hash['AzureWebJobsStorage'] = $storageConnectionString
	$hash['AzureWebJobsDashboard'] = $storageConnectionString
	$hash['FUNCTIONS_EXTENSION_VERSION'] = '~2'
	$hash[$akDistributionConnectionKeyName] = $akDistributionConnectionKeyValue
	
    
    Set-AzureRmWebApp -Name $FunctionAppName -ResourceGroupName $resourceGroupName -Use32BitWorkerProcess $false -AppSettings $hash

    #AlwaysOn
    $WebAppResourceType = 'microsoft.web/sites'
    
    #$WebAppProperties = @{"siteConfig" = @{"AlwaysOn" = $true}}
    
    $ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$FunctionAppName"
    Set-AzureRmResource -ResourceId $ResourceId -PropertyObject $WebAppProperties -Force
	    
    #AddWebAppAlert -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -WebAppName $appName -Location $location -CustomEmails $CustomEmails
	
    # Upload files recursively 
    if ($appdirectory -ne "") {
        UploadFilesUsingFtp -appdirectory $appdirectory -username $username -password $password
    }
    $result = New-Object FtpData
    $result.Host = $url 
    $result.UserName = $username
    $result.Password = $password
    return $result
}

Function UploadFilesUsingFtp([string]$appdirectory, [string]$username, [string]$password) {
    Set-Location $appdirectory
    CreateEmptyDirectory -rootDirectory $appdirectory -username $username -password $password
    $webclient = New-Object -TypeName System.Net.WebClient
    $webclient.Credentials = New-Object System.Net.NetworkCredential($username, $password)
    $files = Get-ChildItem -Path $AppDirectory -Recurse | Where-Object {!($_.PSIsContainer)}
    foreach ($file in $files) {
        $relativepath = (Resolve-Path -Path $file.FullName -Relative).Replace(".\", "").Replace('\', '/')
        $uri = New-Object System.Uri("$url/$relativepath")
        Write-Host "Uploading to $uri.AbsoluteUri" 
        $webclient.UploadFile($uri, $file.FullName)
    } 
    $webclient.Dispose()
}

Function CreateEmptyDirectory([string]$appdirectory, [string]$username, [string]$password) {
    $dirs = dir -Directory -Recurse
    $cred = New-Object System.Net.NetworkCredential($username, $password)
    foreach ($dir in $dirs) {
        $relativepath = (Resolve-Path -Path $dir.FullName -Relative).Replace(".\", "").Replace('\', '/')
        $uri = "$url/$relativepath"
        $request = [system.net.ftpwebrequest]::Create($uri)
        $request.Method = [system.net.webrequestmethods+ftp]::MakeDirectory
        $request.Credentials = $cred
        Write-Host "Uploading to $uri.AbsoluteUri" 
        $request.GetResponse()
        #$request.Dispose();
    }
}

Function AddWebAppAlert ([string]$SubscriptionId, [string]$ResourceGroupName, [string]$WebAppName, [string]$Location, [string]$CustomEmails = "") {
    Set-AzureRmContext -SubscriptionId $SubscriptionId
    $ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"
   	if ($null -eq $CustomEmails) {
        $CustomEmails = ""
    }
    if ($CustomEmails -ne "") {
        $actionEmail = New-AzureRmAlertRuleEmail -CustomEmail $CustomEmails
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "HttpServerErrors5xx"
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "ResponseOver5Sec"
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "RequestsOver1000For5Min"

        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "HttpServerErrors5xx" -MetricName "Http5xx" -Operator GreaterThan -Threshold 2 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "5xx over 2 for 5 minutes"
        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "ResponseOver5Sec" -MetricName "AverageResponseTime" -Operator GreaterThan -Threshold 5 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "Average response over 5 sec for 5 minutes"
        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "RequestsOver1000For5Min" -MetricName "Requests" -Operator GreaterThan -Threshold 1000 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "Total request over 1000 for 5 minutes"
    }
}

Function AddVmAlert ([string]$SubscriptionId, [string]$ResourceGroupName, [string]$VmName, [string]$Location, [string]$Email = "") {
    Set-AzureRmContext -SubscriptionId $SubscriptionId
    $ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$VmName"
    if ($CustomEmails -ne "") {
        $actionEmail = New-AzureRmAlertRuleEmail -CustomEmail $Email
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "CpuOver80For5Min"
        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "CpuOver80For5Min" -MetricName "Percentage CPU" -Operator GreaterThan -Threshold 80 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "Cpu over 80% for 5 minutes"
    }
}


Function validateInput([string]$Readhost)
{
    Switch ($ReadHost) 
     { 
       Y {$result = $true} 
       N {$result =  $false} 
       Default {$result = $false} 
     } 
    return $result
}

Function DownloadContentDistributionFiles([string]$DownloadToFolder,[string]$downloadurl,[string]$cdFile)
{
try {
        if (!(Test-Path -Path $DownloadToFolder)) {
            New-Item -Path $DownloadToFolder -Type Directory -Force -ErrorAction Stop | Out-Null
        }
        else{
			$url = $DownloadToFolder+ "\" + $cdFile
			$wc = New-Object System.Net.WebClient
			$wc.DownloadFile($downloadurl, $url)
			$extractLocation = $DownloadToFolder
			#$fileFolder = $DownloadToFolder +"\" + "contentdistribution\"
			#if((Test-Path -Path $extractLocation))
			#{
			#	Remove-Item –path $extractLocation –recurse
			#}			
			#if (!(Test-Path -Path $extractLocation)) {
			#	New-Item -Path $extractLocation -Type Directory -Force
			#}
			if (Test-Path $extractLocation) {
				Expand-Archive -LiteralPath $url -DestinationPath $extractLocation
			}		
		} 
		return $DownloadToFolder
    }
    catch{
          Write-Error -Message $_.Exception
          throw $_.Exception
    }
 }
