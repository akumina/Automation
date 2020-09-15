cd $PSScriptRoot
$subject= read-host "Please enter the certificate subject"
$pwd= read-host "Please enter the password"
$todaydt = Get-Date
$enddt = $todaydt.AddYears(10)
$cert=New-SelfSignedCertificate -Subject $subject -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" -notafter $enddt
$certPassword = ConvertTo-SecureString -String $pwd -Force -AsPlainText
$pfxFilePath="akumina_v5.pfx"
$certFilePath="akumina_v5.cer"
$outFile="akumina_v5.txt"
Export-PfxCertificate -Cert $cert -FilePath $pfxFilePath -Password $certPassword
Export-Certificate -Cert $cert -FilePath $certFilePath
$clearBytes = get-content $pfxFilePath -Encoding Byte
[System.Convert]::ToBase64String($clearBytes)| Out-File $outFile