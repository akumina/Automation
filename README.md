# Akumina AppManager / ServiceHub Infrastructure / Headless using ARM template.

**Current Version:** AppManager 6.0; PeopleSync 6.0

**Last Version:** AppManager 5.5/5.0/4.8; PeopleSync 5.5/5.0/4.8

## Marketplace Offerings
We recommend you install our applications from Azure Marketplace

* Latest (6.x): https://azuremarketplace.microsoft.com/en-us/marketplace/apps/akumina.akumina-appmanager-web?tab=Overview

## ARM Template
ARM Templates can be executed using 
* Powershell
* DevOps pipeline
* Azure Template Spec
* Service Catalog Managed Application
* Azure Blueprints (some modification required)


To fully configure the application, you need the Application Packages (Web App and Function App Package); please contact your account administrator to request the package URL.


```
For Cosmos DB, a capacity mode can be set to Throughput (default) or Serverless, 
to set desired value please use parameter file or parameter option as -cosmosDbCapacityMode "[Throughput or Serverless]"
```

```
Package Version:
For version 6.0: run files under 6.x
For version 5.5: set packageVersion as empty (default) using parameter file or parameter option as -packageVersion "latest" 
For 5.0: set the package version as latest/ 5.0  using parameter file or parameter option as -packageVersion "5.0"
```


You need to configure the Azure AD application, including scopes and permissions.

Some functionality such as Activity Streams requires certificate-based authentication using the Azure AD application; you may use [common/cert.ps1](https://github.com/akumina/Automation/blob/master/common/cert.ps1) to generate a test certificate.

To learn more about PeopleSync, please visit https://community.akumina.com/knowledge-base/peoplesync-v5/ 

To learn more about Azure AD application, Scope and Permissions, please visit https://community.akumina.com/knowledge-base/graph-api-connection-for-azure-ad/

To learn more about Key Vaults configuration, please visit https://community.akumina.com/knowledge-base/key-vault-configuration-5x/
