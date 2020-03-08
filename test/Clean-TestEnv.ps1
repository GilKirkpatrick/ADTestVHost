Get-VM | ?{ $_.VMName -like 'DC*' } | %{
    Stop-VM $_ -Force
    Remove-VM $_ -Force
    Remove-Item "h:\Hyper-V\$($_.VMName)" -Recurse -Force
}

Get-Job | %{
    Remove-Job $_ -Force
}

Import-Module ADTestVHost -Force