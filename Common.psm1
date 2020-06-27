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

Function Add-AkAppResources([string]$TenantId, [string]$SubscriptionId, [string]$BaseName, [string]$Location, [string]$AadAppName = "", [string]$ResourceGroupName = ""
    , [string]$StorageAccountName = "", [string]$KeyVaultName = "", [string[]]$ReplyUrls = "", [string]$localAppDirectory = "", [string]$CustomEmails
    , [bool]$CreateAppGw = $false, [bool]$CreateRedisCache = $false, [string]$RedisCacheName = "", [bool]$CreateTrafficManager = $false
    , [string]$BackendHostName = "", [string]$PfxFile = "", [string]$appManagerQueryKey = "", [string]$vnetAddressPrefix , [string]$subnetPrefix , [bool]$createWebApp = $false
    , [bool]$createAzureADApp = $false, [bool]$createStorage = $false, [bool]$createKeyVault = $false, [bool]$http20Enabled = $true, [bool]$http20EnabledAppGw = $true
    , [bool]$createFuncApp = $false, [string]$funcAppQueues = "", [string]$funcAppName = "", [bool]$createCosmosDb = $false, [string]$databaseAccountName = "", [string]$databaseName = "") {
     
    if ($BaseName -eq "") {
        $BaseName = $ResourceGroupName
    }
    $HomePage = "https://$BaseName.azurewebsites.net"
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
    if ($funcDistributionAppName -eq "") {
        $funcDistributionAppName = "fn-$appName"
    }
    if ($RedisCacheName -eq "") {
        $RedisCacheName = $appName
    }
    if ($PfxFile -and $CreateAppGw) {
        $SecurePassword = Read-Host -Prompt "Enter Pfx password" -AsSecureString
    }
    if (!$http20Enabled) {
        $http20Enabled = $false
    }
    if (!$http20EnabledAppGw) {
        $http20EnabledAppGw = $false
    }
    #Login-AzureRmAccount -TenantId $TenantId 
    $credentials = Connect-AzureAD -TenantId $TenantId
    $user = Get-AzureRmADUser -UserPrincipalName $credentials.Account.Id
    $appData = Get-AzureRmADApplication -DisplayNameStartWith $AadAppName -ErrorVariable aadAppNotExists -ErrorAction SilentlyContinue
    if ($createAzureADApp) {
        if ($null -eq $appData) {
            Write-Host "Provisioning Aad App started..." -ForegroundColor Cyan
            $appData = Register-AkAdApp -AppName $AadAppName -Uri $HomePage -ReplyUrls $ReplyUrls
            Write-Host "Provisioning Aad App ended..." -ForegroundColor Cyan
        }
        else {
            Write-Host "Provisioning Aad App skipped..." -ForegroundColor Cyan
        }
    }

    Set-AzureRmContext -SubscriptionId $SubscriptionId 
    Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorVariable rgNotExists -ErrorAction SilentlyContinue
    if ($rgNotExists) {
        Write-Host "Provisioning Resource Group started..." -ForegroundColor Cyan
        New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location 
        Write-Host "Provisioning Resource Group ended..." -ForegroundColor Cyan
    }
    else {
        Write-Host "Provisioning Resource Group skipped..." -ForegroundColor Cyan
    }
    if ($createStorage) {
        $storage = Add-AkStorageAccount -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Location $Location
    }

    if ($createWebApp) {
        $wp = Get-AzureRmWebApp -Name $appName
        if ($null -eq $wp) {
            Write-Host "Provisioning webapp started..." -ForegroundColor Cyan
            New-AzureRmResourceGroupDeployment -Name $appName -TemplateFile akwebapp.json -ResourceGroupName $ResourceGroupName -baseResourceName $appName
            if ($http20Enabled) {
                $propertiesObject = @{ 
                    http20Enabled = $true;
                }
                Set-AzureRmResource -PropertyObject $propertiesObject -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Web/sites/config -ResourceName "$appName/web" -ApiVersion 2016-08-01 -Force  
            }
            Write-Host "Provisioning webapp ended..." -ForegroundColor Cyan
        }
        else {
            Write-Host "Provisioning webapp skipped..." -ForegroundColor Cyan
        }
    }
   
    if ($createKeyVault) {
        $storageConnectionString = Get-AkStorageConnectionString -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
        $secretvalue = ConvertTo-SecureString –String $storageConnectionString –AsPlainText –Force 
        $secretName = "StorageConnectionString"
        Add-AkKeyVault -tenantId $TenantId -resourceGroupName $ResourceGroupName -userId $user.Id.Guid.ToString() -appName $appName -KeyVaultName $KeyVaultName -secretName $secretName -secretvalue $secretvalue
        $secretIdUri = Get-AzureKeyVaultSecret -VaultName  $KeyVaultName -Name $secretName
    }
    else {
        Write-Host "Provisioning Keyvault skipped..." -ForegroundColor Cyan
    }
    	
    if ($CreateRedisCache) {
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
        $appGw = "$appName-appgw"
        Get-AzureRmApplicationGateway -Name $appGw -ResourceGroupName $ResourceGroupName  -ErrorVariable agNotExists -ErrorAction SilentlyContinue
        if ($agNotExists) {
            Write-Host "Provisioning App Gateway started..." -ForegroundColor Cyan
            $sslCertificate = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($PfxFile))
            if ($vnetAddressPrefix -eq "") {
                $vnetAddressPrefix = "10.10.0.0/16"
            }
            if ($subnetPrefix -eq "") {
                $subnetPrefix = "10.10.0.0/24"
            }
            $webApps = Get-AzureRmWebApp -Name $appName -ResourceGroupName $ResourceGroupName
            if ($null -eq $webApps) {
                $backendHostName = '$appName.onakumina.com'
            }
            else {
                $backendHostName = $webApps.DefaultHostName.ToString()				
            }

            New-AzureRmResourceGroupDeployment -TemplateFile akappgateway.json -ResourceGroupName $ResourceGroupName -applicationGatewaysName $appName -sslCertificate $sslCertificate -certPassword $securePassword -hostName $backendHostName -backendIPAddresses $backendHostName -vnetAddressPrefix $vnetAddressPrefix -subnetPrefix $subnetPrefix

            if ($http20EnabledAppGw) {
                $gw = Get-AzureRmApplicationGateway -name $appGw -ResourceGroupName $ResourceGroupName
                $gw.EnableHttp2 = $true
                Set-AzureRmApplicationGateway -ApplicationGateway @gw
            }
						
            Write-Host "Provisioning App Gateway ended..." -ForegroundColor Cyan
        }
        else {
            Write-Host "Provisioning App Gateway skipped..." -ForegroundColor Cyan
        }		
    }
	
    if ($CreateTrafficManager -and $CreateAppGw) {
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
    if ($localAppDirectory -ne "") {
        Set-AkAppManagerSettings -configFilePath "$localAppDirectory\interchange.settings.config" -key "akumina:RemoteStorageConnection" -newValue $secretIdUri.Id
        Set-AkAppManagerSettings -configFilePath "$localAppDirectory\interchange.settings.config" -key "akumina:BackgroundProcessorKey" -newValue $backgroundGuid
        Set-AkAppManagerSettings -configFilePath "$localAppDirectory\interchange.settings.config" -key "akumina:LogListener" -newValue "AzureTable"
        if ($CreateRedisCache) {
            Set-AkAppManagerSettings -configFilePath "$localAppDirectory\interchange.settings.config" -key "akumina:PrimaryRedisConnection" -newValue $cacheKeyData.ConnectionString
            Set-AkRedisCacheToUnity -configFilePath "$localAppDirectory\unity.config" 
        }
    }

    if ($createWebApp) {
        $ftp = Update-AkWebApp -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WebAppName $appName -Location $Location -AppDirectory $localAppDirectory -CustomEmails $CustomEmails
    }
    
    $cosmosDbPrimaryKey = Add-AkCosmosDb -createCosmosDb $createCosmosDb -databaseAccountName $databaseAccountName -databaseName $databaseName -Location $Location
    
    if ($createFuncApp) {
        foreach ($queue in $funcAppQueues.Split(",")) {
            Add-AkStorageQueue -ResourceGroupName $ResourceGroupName -queueName $queue -StorageAccountName $StorageAccountName
        }
        $funcAppFtp = Add-AkFuncApp -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -Location $Location -storageAccountName $StorageAccountName -funcAppName $funcAppName -databaseAccountName $databaseAccountName -cosmosDbPrimaryKey $cosmosDbPrimaryKey -databaseName $databaseName
    }
    
    Write-Host "AD App Name: $AadAppName" -ForegroundColor Cyan
    Write-Host "AD App ID: "($appData.AppId) -ForegroundColor Cyan
    Write-Host "AD App Secret: "($appData.AppSecret) -ForegroundColor Cyan
    Write-Host "Storage ConnectionString: "($storage.ConnectionString) -ForegroundColor Cyan
    Write-Host "Secret Id Uri: "($secretIdUri.Id) -ForegroundColor Cyan
    Write-Host "Redis Connection String: "($cacheKeyData.ConnectionString) -ForegroundColor Cyan
    Write-Host "AzureWebSite Url: $HomePage" -ForegroundColor Cyan		
    Write-Host "BackgroundProcessorKey: $backgroundGuid" -ForegroundColor Cyan
    if ($createCosmosDb) {
        Write-Host "Cosmos DB Primary Key: $cosmosDbPrimaryKey" -ForegroundColor Cyan
    }
    if ($createWebApp) {			
        Write-Host "Web App FTP Host: "($ftp.Host) -ForegroundColor Cyan
        Write-Host "Web App FTP User: "($ftp.UserName) -ForegroundColor Cyan
        Write-Host "Web App FTP Password: "($ftp.Password) -ForegroundColor Cyan
    }
    if ($createFuncApp) {
        Write-Host "Function App FTP Host: "($funcAppFtp.Host) -ForegroundColor Cyan
        Write-Host "Function App FTP User: "($funcAppFtp.UserName) -ForegroundColor Cyan
        Write-Host "Function App FTP Password: "($funcAppFtp.Password) -ForegroundColor Cyan
    }
    Write-Host "DONE!" -ForegroundColor Green
}

Function Add-AkCosmosDb([bool]$createCosmosDb, [string]$databaseAccountName, [string]$databaseName, [string]$Location) {
    if ($createCosmosDb) {
        Write-Host "Provisioning CosmosDB started..." -ForegroundColor Cyan
        $outputs = New-AzureRmResourceGroupDeployment -TemplateFile akcosmosdb.json -ResourceGroupName $ResourceGroupName -databaseAccountName $databaseAccountName -databaseName $databaseName -location $Location
        Write-Host "Provisioning CosmosDB ended..." -ForegroundColor Cyan
        return $outputs.Outputs["connectionString"].Value;
    }
    else {
        Write-Host "Provisioning CosmosDB skipped..." -ForegroundColor Cyan
    }
}

Function Add-AkFuncApp([string]$SubscriptionId, [string]$ResourceGroupName, [string]$Location, [string]$storageAccountName, [string]$funcAppName, [string]$databaseAccountName, [string]$cosmosDbPrimaryKey, [string]$databaseName) {
    $wp = Get-AzureRmWebApp -Name $funcAppName
    if ($null -eq $wp) {
        $content = Get-Content "parameters.json" | ConvertFrom-Json
        $funcAppPackageUrl = Get-AkParams  -params $content.parameters -param "funcAppPackageUrl"
        $hostedBlobContainer = Get-AkParams  -params $content.parameters -param "hostedBlobContainer"
        Write-Host "Provisioning function app started..." -ForegroundColor Cyan
        $conn = "AccountEndpoint=https://" + $databaseAccountName + ".documents.azure.com:443/;AccountKey=" + $cosmosDbPrimaryKey
        New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -funcAppName $funcAppName -cosmosDBConnectionString $conn -storageAccountName $storageAccountName -hostedBlobContainer $hostedBlobContainer -TemplateFile akfunc.json -location $Location
        Write-Host "Provisioning function app ended..." -ForegroundColor Cyan
       
        [xml] $xml = (Get-AzureRmWebAppPublishingProfile -Name $funcAppName -ResourceGroupName $ResourceGroupName -OutputFile null)

        # Extract connection information from publishing profile
        $username = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@userName").value
        $password = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@userPWD").value
        $url = $xml.SelectNodes("//publishProfile[@publishMethod=`"FTP`"]/@publishUrl").value
        
        if ($funcAppPackageUrl -ne "") {
            $DownloadToFolder = Get-AkTempWorkDir
            $funcAppFileName = (split-path -Path $funcAppPackageUrl -leaf).split("?")[0]
            Request-AkInstallPackage -DownloadToFolder $DownloadToFolder -downloadPath $funcAppPackageUrl -downloadFile $funcAppFileName
            Publish-AkFtp -appdirectory $DownloadToFolder -username $username -password $password
        }

        $result = New-Object FtpData
        $result.Host = $url 
        $result.UserName = $username
        $result.Password = $password
        return $result
    }
    else {
        Write-Host "Provisioning function app skipped..." -ForegroundColor Cyan
    }
}

Function Add-AkKeyVault([string] $tenantId, [string] $resourceGroupName, [string] $userId, [string] $appName, [string]  $KeyVaultName, [string] $secretName, [Security.SecureString] $secretvalue) {
    $servicePrincipals = $null
    $iteration = 0
    $objectId = $userId
    $wp = Get-AzureRmWebApp -Name $appName
    if ($null -ne $wp) {     
        
        while ($iteration -le 12) {
            $servicePrincipals = get-azurermadserviceprincipal -SearchString $appName
            if ($null -ne $servicePrincipals) {
                break
            }
            Start-Sleep -s 5
            $iteration++
        }
        $objectId = $servicePrincipals[0].Id
    }
    $kv = Get-AzureRmKeyVault -VaultName $KeyVaultName
    if ($null -eq $kv) {
        Write-Host "Provisioning Keyvault started..." -ForegroundColor Cyan
        New-AzureRmResourceGroupDeployment -Name AkWebAppKeyVault -tenantId $TenantId -keyVaultName $KeyVaultName -objectId $objectId -secretName $secretName -secretValue $secretValue -TemplateFile akkeyvault.json -ResourceGroupName $resourceGroupName -userId  $userId
        Write-Host "Provisioning Keyvault ended..." -ForegroundColor Cyan
    }
    else {
        Write-Host "Provisioning Keyvault skipped..." -ForegroundColor Cyan
    }
}

Function Add-AkStorageQueue([string] $resourceGroupName, [string] $queueName, [string]$StorageAccountName) {	
    $storage = Get-AzureRmStorageAccount -ResourceGroupName $resourceGroupName -AccountName $StorageAccountName
    $storageContext = $storage.Context
    $azureStorageQueue = Get-AzureStorageQueue –Context $storageContext | Where-Object { $_.Name -eq $queueName }
    if (-not $azureStorageQueue) { 
        New-AzureStorageQueue -Name  $queueName -Context $storageContext
    }
}

Function New-AkPassword {
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
Function Add-AkResourcePermission($requiredAccess, $exposedPermissions, [string]$requiredAccesses, [string]$permissionType) {
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

Function Get-AkAppPermissions {
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

Function Get-AkDeligatedPermissions {
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

# Exemple: Get-AkRequiredPermissions "Microsoft Graph"  "Graph.Read|User.Read"
Function Get-AkRequiredPermissions([string] $appId, [string] $requiredDelegatedPermissions, [string]$requiredApplicationPermissions) {
    $sp = Get-AzureADServicePrincipal -Filter "AppId eq '$appId'"
    $requiredAccess = New-Object Microsoft.Open.AzureAD.Model.RequiredResourceAccess
    $requiredAccess.ResourceAppId = $appid 
    $requiredAccess.ResourceAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]

    # $sp.Oauth2Permissions | Select Id,AdminConsentDisplayName,Value: To see the list of all the Delegated permissions for the application:
    if ($requiredDelegatedPermissions) {
        Add-AkResourcePermission $requiredAccess -exposedPermissions $sp.Oauth2Permissions -requiredAccesses $requiredDelegatedPermissions -permissionType "Scope"
    }
    
    # $sp.AppRoles | Select Id,AdminConsentDisplayName,Value: To see the list of all the Application permissions for the application
    if ($requiredApplicationPermissions) {
        Add-AkResourcePermission $requiredAccess -exposedPermissions $sp.AppRoles -requiredAccesses $requiredApplicationPermissions -permissionType "Role"
    }
    return $requiredAccess
}  

Function Register-AkAdApp ([string]$AppName, [string]$Uri = "https://localhost:44305", [string[]]$ReplyUrls = @("https://localhost:44305")) {
    #ObjectId                             AppId                                DisplayName
    #d89f3c59-37de-453b-b95f-18d313631b39 00000003-0000-0000-c000-000000000000 Microsoft Graph
    #f18ff2fd-ccff-4135-9ba4-11c8e8bca5bb 00000002-0000-0000-c000-000000000000 Windows Azure Active Directory
    #4c50a7fa-08bd-45ab-aefc-e93fe865bc9d 00000003-0000-0ff1-ce00-000000000000 Microsoft.SharePoint
    #21db81ce-bd4c-4b4e-bda9-2efb9dbb5147 00000004-0000-0ff1-ce00-000000000000 Microsoft.Lync
    $requiredResourcesAccess = New-Object "System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]"
    $appId = "00000003-0000-0000-c000-000000000000"
    #$appPermissions=Get-AkAppPermissions($appId)
    #$deligatedPermission=Get-AkDeligatedPermissions($appId)
    $appPermissions = "Group.ReadWrite.All"
    $deligatedPermission = "Calendars.Read|Directory.AccessAsUser.All|Group.Read.All|Group.ReadWrite.All|MailboxSettings.ReadWrite|Tasks.Read|User.Read.All|Mail.Read"    
    $microsoftGraphRequiredPermissions = Get-AkRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
    $requiredResourcesAccess.Add($microsoftGraphRequiredPermissions)  

    #$appId = "00000002-0000-0000-c000-000000000000"
    #$appPermissions = "Directory.Read.All"
    #$deligatedPermission = ""
    #$wadRequiredPermissions = Get-AkRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
    #$requiredResourcesAccess.Add($wadRequiredPermissions)  
    
    $appId = "00000003-0000-0ff1-ce00-000000000000"    
    $appPermissions = ""
    $deligatedPermission = "AllSites.FullControl|MyFiles.Read|MyFiles.Write|Sites.Search.All|TermStore.Read.All|User.ReadWrite.All"     
    
    $microsoftSpRequiredPermissions = Get-AkRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
    $requiredResourcesAccess.Add($microsoftSpRequiredPermissions)  
    
    #$appId = "00000004-0000-0ff1-ce00-000000000000"
    #$appPermissions = "Conversations.Chat"
    #$deligatedPermission = "User.ReadWrite|Contacts.ReadWrite"     
    #$lyncRequiredPermissions = Get-AkRequiredPermissions -appId $appId -requiredDelegatedPermissions $deligatedPermission -requiredApplicationPermissions $appPermissions
    #$requiredResourcesAccess.Add($lyncRequiredPermissions)  
    
    $identifierUris = $uri + "/" + [GUID]::NewGuid().ToString()

    # Create the Azure AD app
    $aadApplication = New-AzureADApplication -DisplayName $AppName `
        -Homepage $Uri `
        -ReplyUrls $ReplyUrls `
        -IdentifierUris $identifierUris `
        -RequiredResourceAccess $requiredResourcesAccess `
        -Oauth2AllowImplicitFlow $true `
        -Oauth2AllowUrlPathMatching $true

    $pwdKeyValue = New-AkPassword
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
Function Set-AkAppManagerSettings([string] $configFilePath, [string] $key, [string] $newValue) {
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

Function Set-AkRedisCacheToUnity([string] $configFilePath) {
    $content = Get-Content $configFilePath | Out-String
    [xml] $xmlContent = $content
    $target = (($xmlContent.unity.container | Where-Object { $_.name -eq "caching" }).register | where { $_.type -eq "ICachingService" })
    $target.mapTo = "RedisCachingService"
    $xmlContent.save($configFilePath)
}

Function Set-AkAppSettings([string] $configFilePath, [string] $key, [string] $newValue) {
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

Function Add-AkStorageAccount {
    [OutputType([StorageData])]
    param([string]$SubscriptionId, [string]$ResourceGroupName, [string]$StorageAccountName, [string]$Location, $SkuName = "Standard_LRS")
    $st = Get-AzureRmStorageAccountNameAvailability -Name $StorageAccountName
    if ($st.NameAvailable) {
        Write-Host "Provisioning storage account started..." -ForegroundColor Cyan
        New-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Location $Location -SkuName $SkuName
        Write-Host "Provisioning storage account ended..." -ForegroundColor Cyan
    }
    $result = New-Object StorageData
    $result.ConnectionString = Get-AkStorageConnectionString -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
    return $result
}

Function Update-AkWebApp {
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
    $hash = @{ }
    ForEach ($kvp in $appSettings) {
        $hash[$kvp.Name] = $kvp.Value
    }
    $hash['SCM_COMMAND_IDLE_TIMEOUT'] = "3600"
    
    Set-AzureRmWebApp -Name $appName -ResourceGroupName $resourceGroupName -Use32BitWorkerProcess $false -AppSettings $hash
  
    $WebAppProperties = @{"siteConfig" = @{"AlwaysOn" = $true } }
    #$webAppResource = Get-AzureRmResource -ResourceType $WebAppResourceType -ResourceGroupName $ResourceGroupName
    $ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"
    Set-AzureRmResource -ResourceId $ResourceId -PropertyObject $WebAppProperties -Force
	    
    Add-AkWebAppAlert -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -WebAppName $appName -Location $location -CustomEmails $CustomEmails
	
    # Upload files recursively 
    if ($appdirectory -ne "") {
        Publish-AkFtp -appdirectory $appdirectory -username $username -password $password
    }
    $result = New-Object FtpData
    $result.Host = $url 
    $result.UserName = $username
    $result.Password = $password
    return $result
}

Function Get-AkStorageConnectionString {
    [OutputType([string])]
    param([string] $ResourceGroupName, [string] $StorageAccountName)
    $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName).Value[0]
    $storageConnectionString = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$storageAccountKey"
    return $storageConnectionString;
}

Function Publish-AkFtp([string]$appdirectory, [string]$username, [string]$password) {
    Set-Location $appdirectory
    Add-EmptyDirectory -rootDirectory $appdirectory -username $username -password $password
    $webclient = New-Object -TypeName System.Net.WebClient
    $webclient.Credentials = New-Object System.Net.NetworkCredential($username, $password)
    $files = Get-ChildItem -Path $AppDirectory -Recurse | Where-Object { !($_.PSIsContainer) }
    foreach ($file in $files) {
        $relativepath = (Resolve-Path -Path $file.FullName -Relative).Replace(".\", "").Replace('\', '/')
        $uri = New-Object System.Uri("$url/$relativepath")
        Write-Host "Uploading to $uri.AbsoluteUri" 
        $webclient.UploadFile($uri, $file.FullName)
    } 
    $webclient.Dispose()
}

Function Add-EmptyDirectory([string]$appdirectory, [string]$username, [string]$password) {
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

Function Add-AkWebAppAlert ([string]$SubscriptionId, [string]$ResourceGroupName, [string]$WebAppName, [string]$Location, [string]$CustomEmails = "") {
    Set-AzureRmContext -SubscriptionId $SubscriptionId
    $ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"
   	if ($null -eq $CustomEmails) {
        $CustomEmails = ""
    }
    if ($CustomEmails -ne "") {
        $actionEmail = New-AzureRmAlertRuleEmail -CustomEmail $CustomEmails
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "HttpServerErrors5xx"
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "HttpServerErrors4xx"
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "ResponseOver5Sec"
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "RequestsOver1000For5Min"

        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "HttpServerErrors5xx" -MetricName "Http5xx" -Operator GreaterThan -Threshold 2 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "5xx over 2 for 5 minutes"		
        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "HttpServerErrors4xx" -MetricName "Http4xx" -Operator GreaterThan -Threshold 2 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "4xx over 2 for 5 minutes"		
        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "ResponseOver5Sec" -MetricName "AverageResponseTime" -Operator GreaterThan -Threshold 5 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "Average response over 5 sec for 5 minutes"
        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "RequestsOver1000For5Min" -MetricName "Requests" -Operator GreaterThan -Threshold 1000 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "Total request over 1000 for 5 minutes"
    }
}

Function Add-AkWebAppAlertV2 ([string]$SubscriptionId, [string]$ResourceGroupName, [string]$WebAppName, [string]$Location, [string]$CustomEmails = "") {
    Set-AzureRmContext -SubscriptionId $SubscriptionId
    $ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"
   	if ($null -eq $CustomEmails) {
        $CustomEmails = ""
    }
    if ($CustomEmails -ne "") {		
        $actionEmail = New-AzureRmAlertRuleEmail -CustomEmail $CustomEmails
        Remove-AzMetricAlertRuleV2 -ResourceGroup $ResourceGroupName -Name "HttpServerErrors5xx"
        Remove-AzMetricAlertRuleV2 -ResourceGroup $ResourceGroupName -Name "HttpServerErrors4xx"
        Remove-AzMetricAlertRuleV2 -ResourceGroup $ResourceGroupName -Name "ResponseOver5Sec"
        Remove-AzMetricAlertRuleV2 -ResourceGroup $ResourceGroupName -Name "RequestsOver1000For5Min"

        Add-AzMetricAlertRuleV2 -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "HttpServerErrors5xx" -MetricName "Http5xx" -Operator GreaterThan -Threshold 2 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "5xx over 2 for 5 minutes"		
        Add-AzMetricAlertRuleV2 -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "HttpServerErrors4xx" -MetricName "Http4xx" -Operator GreaterThan -Threshold 2 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "4xx over 2 for 5 minutes"		
        Add-AzMetricAlertRuleV2 -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "ResponseOver5Sec" -MetricName "AverageResponseTime" -Operator GreaterThan -Threshold 5 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "Average response over 5 sec for 5 minutes"
        Add-AzMetricAlertRuleV2 -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "RequestsOver1000For5Min" -MetricName "Requests" -Operator GreaterThan -Threshold 1000 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "Total request over 1000 for 5 minutes"
    }
}

Function Add-AkVmAlert ([string]$TenantId, [string]$SubscriptionId, [string]$ResourceGroupName, [string]$VmName, [string]$Location, [string]$Email = "") {
    Set-AzureRmContext -SubscriptionId $SubscriptionId
    $ResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$VmName"
    if ($CustomEmails -ne "") {
        $actionEmail = New-AzureRmAlertRuleEmail -CustomEmail $Email
        Remove-AzureRmAlertRule -ResourceGroup $ResourceGroupName -Name "CpuOver80For5Min"
        Add-AzureRmMetricAlertRule -Location "$Location" -ResourceGroup $ResourceGroupName -TargetResourceId "$ResourceId" -Name "CpuOver80For5Min" -MetricName "Percentage CPU" -Operator GreaterThan -Threshold 80 -WindowSize 00:05:00 -TimeAggregationOperator Total -Action $actionEmail -Description "Cpu over 80% for 5 minutes"
    }
}

Function Request-AkInstallPackage([string]$DownloadToFolder, [string]$downloadPath, [string]$downloadFile) {
    try {
        if (!(Test-Path -Path $DownloadToFolder)) {
            New-Item -Path $DownloadToFolder -Type Directory -Force -ErrorAction Stop | Out-Null
        }
        else {
            $url = $DownloadToFolder + "\" + $downloadFile
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($downloadPath, $url)
            if (Test-Path $DownloadToFolder) {
                Expand-Archive -LiteralPath $url -DestinationPath $DownloadToFolder
            }		
        } 
        Remove-Item –path $DownloadToFolder\* -include *.zip
        return $DownloadToFolder
    }
    catch {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

Function Get-AkTempWorkDir() {
    $newGuid = [guid]::newguid()
    $tempFolder = $env:temp
    $workDir = "$tempFolder\Akumina"
    if ((Test-Path -Path $workDir)) {
        Get-ChildItem $workDir -Recurse | Remove-Item -Force
    }
    $workDir = "$workDir\$newGuid"
    New-Item -Path $workDir\ -ItemType directory | Out-Null
    return $workDir;
}

Function Get-AkParams {
    [OutputType([string])]
    param([System.Object] $params, [string] $param)
    $val = $params.$param.value
    $displayName = $params.$param.metadata.description
    if ($val -eq "") {
        $val = read-host $displayName
    }
    else { Write-Host "$displayName= " $val }
    return $val;
}

Function Convert-AkInput([string]$Readhost) {
    Switch ($ReadHost) { 
        Y { $result = $true } 
        N { $result = $false } 
        Default { $result = $false } 
    } 
    return $result
}