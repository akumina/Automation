# Akumina AppManager / ServiceHub Infrastructure / Headless using ARM template.

**Active Version in Main Folder:** `web-solution-7.x`

**Archived Versions:** Older template versions are in `archived/`.

For legacy version details, see `archived/README.md`.

## Marketplace Offerings
We recommend you install our applications from Azure Marketplace

* Managed Application Offer: https://marketplace.microsoft.com/en-us/product/akumina.akumina-ai-digital-workplace?tab=overview
* SaaS Offer: https://marketplace.microsoft.com/en-us/product/akumina.akuminaaidigitalworkplace?tab=Overview

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


You need to configure the Azure AD application, including scopes and permissions.

You can use [common/Register-AadApp.ps1](https://github.com/akumina/Automation/blob/master/common/Register-AadApp.ps1) to create an Azure AD application with the required permissions.

Some functionality such as Activity Streams requires certificate-based authentication using the Azure AD application; you may use [common/cert.ps1](https://github.com/akumina/Automation/blob/master/common/cert.ps1) to generate a test certificate.
