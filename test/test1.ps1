# Test remote PS arguments and closures
$securePassword = ConvertTo-SecureString '!@#123qwe' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential "Administrator", $securePassword

$script:scriptVar = "scriptVar"
$localVar = "localVar"

$localSplat = @{
    'scriptVar'=$script:scriptVar;
    'localVar'=$localVar;
    'cred'=$cred;
    'archiveFile'="C:\foo\bar\baz\archive.zip"
}

$vm = Get-VM -VMName DC1
$pss = New-PSSession -VMId $vm.ID -Credential $cred
Invoke-Command -Session $pss -ScriptBlock {
    Write-Host "scriptVar '$($using:script:scriptVar)' localVar '$using:localVar' cred '$using:cred' username '$($using:cred.UserName)'"
    Write-Host "using:localSplat.scriptVar $($using:localSplat.scriptVar)"
    Write-Host (Split-Path $using:localSplat.archiveFile -Parent)
}
Remove-PSSession $pss