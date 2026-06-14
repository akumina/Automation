# Archived Akumina ARM Templates

This folder contains legacy Akumina ARM template solutions that are no longer the active main version.

## Archived Versions

- AppManager 6.0, 5.5, 5.0, 4.8
- PeopleSync 6.0, 5.5, 5.0, 4.8

## Folder Contents

- `web-solution-6.x/`
- `web-solution-5.x/`
- `web-solution-4.x/`

## Package Version Notes (Legacy)

For legacy deployments:

- Version 6.0: run files under `web-solution-6.x`
- Version 5.5: set `packageVersion` as empty/default or use `-packageVersion "latest"`
- Version 5.0: use `-packageVersion "5.0"` (or latest when applicable)

## Legacy Guidance

Some legacy functionality (for example Activity Streams) may require certificate-based authentication using an Azure AD application.

To generate a test certificate, use:
- [common/cert.ps1](https://github.com/akumina/Automation/blob/master/common/cert.ps1)

Legacy documentation links:

- PeopleSync v5: https://community.akumina.com/knowledge-base/peoplesync-v5/
- Azure AD app scopes and permissions: https://community.akumina.com/knowledge-base/graph-api-connection-for-azure-ad/
- Key Vault configuration 5.x: https://community.akumina.com/knowledge-base/key-vault-configuration-5x/
