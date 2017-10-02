<#
.SYNOPSIS
    .
.DESCRIPTION
    .
.PARAMETER Thumbprint
    The thumbprint of the certificate that should be used for signing. If no thumbprint is specified, the certificate stores will be searched for a valid code signing certificate.
.PARAMETER Path
    Specifies the path where to look for the files to be processed.
.EXAMPLE
    C:\PS> 
    <Description of example>
.NOTES
    Author: Florian Mücke
    Date:   October, 1st 2017
#>
    
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, HelpMessage="File or path of file to sign")]
        [string]$FileOrPath,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, HelpMessage="Thumbprint of code signing certificate")]
        [string]$Thumbprint = $null,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, HelpMessage="Pattern of files to sign. Separated by commas.")]
        [string]$Pattern = $null
)

#Write-Host "FileOrPath=$FileOrPath"
#Write-Host "Thumbprint=$Thumbprint"
#Write-Host "Pattern=$Pattern"
    
# ------------------


function WriteCertInfo($cert) {
    Write-Host "Signing certificate used"
	Write-Host "  thumb  :"$cert.Thumbprint
    Write-Host "  expires:"$cert.GetExpirationDateString()
    Write-Host "  path   :"$cert.PSParentPath
    Write-Host "  name   :"$cert.Subject
    Write-Host "  issuer :"$cert.Issuer
}

function GetSigningCert($thumb) {
    if ($thumb) {
        try {
            $cert = (gci Cert: -Recurse | Where-Object {$_.Thumbprint -eq $thumb})[0]
            return $cert
        } catch {        
            Write-Warning "Certificate for thumbprint $thumb could not be found."
        }
    }
    
    $cert = (gci Cert: -Recurse -CodeSigningCert)[0]
    return $cert
}

function HasValidSignature($file) {
    $state = $(get-AuthenticodeSignature $file.FullName).Status
    return ($state.ToString() -eq "Valid")
}

function SignFileWithTimestamp($file, $cert, $timestampServer)
{
    $result = (set-AuthenticodeSignature -Certificate $cert -HashAlgorithm sha256 -TimestampServer $timestampServer $file.FullName)
    Write-Host "  signed with timestamp:" $file.FullName
}

function SignFileNoTimestamp($file, $cert)
{
    $result = (set-AuthenticodeSignature -Certificate $cert -HashAlgorithm sha256 $file.FullName)
    Write-Host "  signed:" $file.FullName
}

function SignFileWithTimestampAndRetry($file, $cert, [string[]]$timestampServers)
{
    foreach($server in $timestampServers)
    {
        Try 
        {
            SignFileWithTimestamp $file $cert $server
            return
        }
        Catch 
        {
            Write-Warning $_.Exception.Message
            continue
        }
        return
    }
    throw "Unable to sign file with any of the $timestampServers.Count specified timeservers" 
}

function SelectFiles($folder, $pattern)
{
   return Get-ChildItem $folder -Recurse -Include $pattern.Split(",")
}

# ----------------------- Main -------------------------------------

$cert = GetSigningCert $Thumbprint
WriteCertInfo $cert

$timestampServers = @(
    "http://timestamp.verisign.com/scripts/timestamp.dll", 
    "http://timestamp.globalsign.com/scripts/timstamp.dll",
    "http://time.certum.pl",
    "http://timestamp.verisign.com/scripts/timstamp.dll",
    "http://timestamp.comodoca.com/authenticode"
)

$isDir = ((Get-Item $FileOrPath) -is [System.IO.DirectoryInfo])
if ($isDir -and ($Pattern -notmatch "\*") -and ($Pattern -notmatch "\?"))
{
    throw "Pattern does not contain any wildcards"
}

$files = if ($isDir) { SelectFiles $FileOrPath $Pattern } else { (gci $FileOrPath) }

$skipCount = 0
$signCount = 0

$duration = Measure-Command { foreach ($file in $files)
    {
        if (HasValidSignature $file)
        {
            Write-Host "  skipping" $file        
            $skipCount++
        }
        else
        {
            SignFileWithTimestampAndRetry $file $cert ($timestampServers)
            $signCount++
        }
    }
}

Write-Host "Signed $signCount files in $duration. Skipped $skipCount already signed files."
