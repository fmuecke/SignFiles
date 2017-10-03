# SignFiles
Powershell script to sign code - including timestamps

## What problems does it solve?
- simple to use
- sign multiple files at once
- sign files in subdirectories as well
- do not overwrite existing signatures
- (more) robust timestamping with different timeservers

## I need a code signing certificate!
You need to buy one.
Or you can create one with powershell (Windows 10) for testing purposes
```powershell
New-SelfSignedCertificate -CertStoreLocation cert:\currentuser\my `
  -Subject "CN=Test Code Signing" `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
  -KeyExportPolicy Exportable `
  -KeyUsage DigitalSignature `
  -Type CodeSigningCert
```
see [Stackoverflow Question](https://serverfault.com/questions/824574/create-code-signing-certificate-on-windows-for-signing-powershell-scripts)
