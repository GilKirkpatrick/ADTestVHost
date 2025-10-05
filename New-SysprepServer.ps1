# Prepare server installation for sysprep
try {
    $vm = New-VM -Name Test -MemoryStartupBytes 8192MB -NoVHD -SwitchName External -Path 'E:\Hyper-V\Test' -Generation 2 -Verbose
    Enable-VMIntegrationService -VM $vm -Name 'Guest Service Interface', 'Heartbeat', 'Key-Value Pair Exchange', 'Shutdown', 'Time Synchronization', 'VSS'
    Get-VMNetworkAdapter -VM $vm | Connect-VMNetworkAdapter -SwitchName External
    $vhdPath = "$($vm.Path)\Virtual Hard Disks\$($vm.Name).vhdx"
    if (Test-Path $vhdPath) {
        Remove-Item $vhdPath -Force
    }
    $vhd = New-VHD -Dynamic -SizeBytes 40GB -Path $vhdPath
    $bootVhd = Add-VMHardDiskDrive -VM $vm -Path $vhd.Path -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -Passthru
    $dvd = Add-VMDvdDrive -VM $vm -Path 'F:\ISOs and installers\en-us_windows_server_2025_updated_april_2025_x64_dvd_ea86301d.iso' -ControllerNumber 0 -ControllerLocation 1 -Passthru
    Add-VMHardDiskDrive -VM $vm -Path 'F:\HyperV Images\Utilities.vhdx' -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 2
    Set-VMFirmware -VM $vm -BootOrder @($dvd, $bootVhd) | Out-Null
    Start-VM -VM $vm | Out-Null
    Write-Output "Waiting for VM to start..."
    Wait-VM -VM $vm -For IPAddress
}
catch {
    throw "Failed creating VM $_"
}
