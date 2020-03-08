$Environment = @{
    'BaseImage' = "E:\Hyper-V\Saved VHDs\WS2019-Base.vhdx";
    'VMFolder' = "H:\Hyper-V";
    'PowerShellModules' = @("H:\dev\ADTestEnv\ADTestVHost", "H:\dev\ADTestEnv\S.DS.P");
    'ModulesArchive' = 'C:\Utilities\PowerShell\Modules\PowerShell.zip'
}

$Forest = @{
    'VSwitchName' = "External";
    'Password'='!@#123qwe';
    'MachineNamePattern' = "DC{0}";
    'IPPattern' = "10.1.0.{0}"
}

Function New-ADTestDomain {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$DomainName,
        [Parameter()][String]$MachineNamePattern = $Forest.MachineNamePattern,
        [Parameter()][String]$IPPattern = $Forest.IPPattern,
        [Parameter()][int]$DCCount = 1
    )

    $jobs = @()
    $firstDC = $True
    for($dcNumber = 1; $dcNumber -le $DCCount; $dcNumber++){
        $vmName = $MachineNamePattern -f $dcNumber
        $ipAddress = $IPPattern -f $dcNumber
        $dnsAddress = '127.0.0.1'

        $vm = New-ADTestServer -VMName $vmName -Start -Wait
        Initialize-ADTestServer -Vm $vm -IPAddress $ipAddress -DNSAddress $dnsAddress -ComputerName $vmName -Passthru -Wait -Verbose:($Verbose -eq $True)

        if($firstDC){
            Initialize-ADTestDC -VM $vm -DomainName $DomainName -IsFirstDc -Verbose:($Verbose -eq $True)
            Wait-ForADTestLdap -VM $vm -Domain $DomainName -Verbose:($Verbose -eq $True)
            $firstDC = $False
            $dnsAddress = $ipAddress # The IP of the first DC will be the DNS address for all the others
        }
        else {
            $jobs += Start-Job -ScriptBlock {

            }
            Initialize-ADTestDC -VM $vm -DomainName $DomainName -Verbose:($Verbose -eq $True)
        }
    }
}

Function Initialize-ADTestDC {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]$Vm,
        [Parameter(Mandatory=$True)][String]$DomainName,
        [Parameter()][Switch]$IsFirstDc,
        [Parameter()][Switch]$Passthru
    )
    # Import-Module ADTestVHost
    # $vm = Get-VM DC1
    # Initialize-ADTestDC -Vm $vm -DomainName foo.local -IsFirstDC
    try {
        $securePassword = $(ConvertTo-SecureString $Forest.Password -AsPlainText -Force).Lengthcle
        $cred = New-Object System.Management.Automation.PSCredential "Administrator", $securePassword;

        if($IsFirstDc){
            Invoke-Command -VMId $Vm.Id -Credential $cred -ScriptBlock {
                Install-ADDSForest -SkipPreChecks -SafeModeAdministratorPassword $using:securePassword -DomainName $using:DomainName -InstallDns -Force
            }
        }
        else {
            Invoke-Command -VMId $Vm.Id -Credential $cred -ScriptBlock {
                $cred = New-Object System.Management.Automation.PSCredential "$($using:DomainName)\Administrator", $using:securePassword
                Install-ADDSDomainController -SkipPreChecks -SafeModeAdministratorPassword $securePassword -Credential $cred -DomainName $using:DomainName -InstallDns -Force
            }
        }
        if($Passthru) {
            return $vm
        }
    }
    catch {
        Throw "From PromoteADTestDC: $_"
    }
}

Function Get-LocalCredential() {
    $securePassword = $(ConvertTo-SecureString $Forest.Password -AsPlainText -Force)
    return New-Object System.Management.Automation.PSCredential "Administrator", $securePassword
}

Function Wait-ForADTestLdap {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]$Vm,
        [Parameter(Mandatory=$True)]$DomainName
    )
    # Wait for the DC to be running before tring to connect
    Wait-VM -VM $vm -For Heartbeat

    $securePassword = $(ConvertTo-SecureString $Forest.Password -AsPlainText -Force)
    $cred = New-Object System.Management.Automation.PSCredential "$DomainName\Administrator", $securePassword

    Invoke-Command -VMId $Vm.Id -Credential $cred -ScriptBlock {
        # Create a connection object with a short timeout
        # Spin loop trying to retrieve RootDSE from local DC
        while($null -eq $rootDSE) {
            if($null -eq $c){
                $c = Get-LdapConnection -Timeout (New-Object System.TimeSpan(0, 0, 5)) -Verbose:($Verbose -eq $True)
            }
            else {
                $rootDSE = Get-RootDSE -LdapConnection $c -Verbose:($Verbose -eq $True)
            }
        }
        return $rootDSE
    }
}

Function Initialize-ADTestServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]$Vm,
        [Parameter(Mandatory=$True)][String]$IPAddress,
        [Parameter(Mandatory=$True)][String]$DNSAddress,
        [Parameter(Mandatory=$True)][String]$ComputerName,
        [Parameter()][Switch]$Wait,
        [Parameter()][Switch]$Passthru
    )
    # $vm = get-vm DC1
    # Import-Module ADTestVHost -Force
    # Initialize-ADTestServer -vm $vm -IPAddress 10.1.0.1 -DNSAddress 127.0.0.1 -ComputerName DC1
    # Make an archive containing the PowerShell folders, and copy to the target VM

    $tempFilename = [System.IO.Path]::GetTempFileName() -replace '\.tmp','.zip'
    Compress-Archive -Path $Environment.PowerShellModules -DestinationPath $tempFilename -Force -Verbose:($Verbose -eq $True)

    Copy-VMFile -VM $Vm -SourcePath $tempFilename -FileSource Host -DestinationPath $Environment.ModulesArchive -CreateFullPath -Force -Verbose:($Verbose -eq $True)

    # This is where to copy other files and applications that need to be installed

    $securePassword = ConvertTo-SecureString $Forest.Password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential "Administrator", $securePassword

    $pss = New-PSSession -VMId $Vm.Id -Credential $cred
    Invoke-Command -Session $pss -ScriptBlock {
        # The Hyper-V PoSh module is a prereq for this one
        Install-WindowsFeature -Name 'Hyper-V-PowerShell' -Verbose:($Verbose -eq $True)

        # Expand the archive of PowerShell commands
        Expand-Archive -Path $using:Environment.ModulesArchive -DestinationPath (Split-Path -Path $using:Environment.ModulesArchive -Parent) -Verbose:($Verbose -eq $True)

        # Allow unsigned PowerShell modules
        # Should change to AllSigned, or import code signing cert intro Trusted Publishers and Trusted Root CAs
        # https://community.spiceworks.com/how_to/153255-windows-10-signing-a-powershell-script-with-a-self-signed-certificate
        Set-ExecutionPolicy Bypass -Scope LocalMachine

        # Set PSModulePath for the current session and permanently for the current user
        $env:PSModulePath = "$(Split-Path -Path $using:Environment.ModulesArchive -Parent);$env:PSModulePath"
        [System.Environment]::SetEnvironmentVariable('PSModulePath', $env:PSModulePath, 'Machine')

        Import-Module ADTestVHost, ServerManager, S.DS.P -Verbose:($Verbose -eq $True)

        # Disable auto-startup of Server Mangler because it is annoying
        Get-ScheduledTask -TaskName 'ServerManager' | Disable-ScheduledTask

        Write-Verbose "IPAddress: $using:IPAddress DNSAddress: $using:DNSAddress ComputerName: $using:ComputerName"

        # Install AD components
        Install-WindowsFeature AD-Domain-Services -Verbose:($Verbose -eq $True)
        Install-WindowsFeature RSAT-ADDS -IncludeAllSubFeature -Verbose:($Verbose -eq $True)

        # Configure IP and DNS of the first Ethernet adapter
        $iface = (Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -match "^Ethernet.*"} | Select-Object -First 1)
        $iface | New-NetIPAddress -IPAddress $using:IPAddress -PrefixLength 24 -Verbose:($Verbose -eq $True)
        $iface | Set-DnsClientServerAddress -ServerAddresses @($using:DNSAddress) -Verbose:($Verbose -eq $True)

        # Rename the computer and restart it. This should always be the last step.
        Write-Verbose "Renaming computer to $using:ComputerName and restarting"
        Rename-Computer -NewName $using:ComputerName -Restart
    }
    Remove-PSSession $pss

    if($Wait) {
        Wait-VM -VM $Vm -For Heartbeat
    }

    if($Passthru) {
        return $Vm
    }
}

Function New-ADTestServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$VMName,
        [Parameter()][String]$BaseImage = $Environment.BaseImage,
        [Parameter()][String]$VMFolder = $Environment.VMFolder,
        [Parameter()][String]$VSwitchName = $Forest.VSwitchName,
        [Parameter()][uint64]$Memory = 2048MB,
        [Parameter()][Switch]$Start,
        [Parameter()][Switch]$Wait
    )

    try {
        if($null -eq (Get-VMSwitch -Name $VSwitchName -ErrorAction Ignore)){
            New-VMSwitch -Name $VSwitchName -SwitchType Internal
        }
        if($null -ne (Get-VM -Name $VMName -ErrorAction Ignore)){
            Throw "VM $VMName already exists"
        }
        $vm = New-VM -Name $VMName -MemoryStartupBytes $Memory -NoVHD -SwitchName $VSwitchName -Path $VMFolder -Generation 2
        Enable-VMIntegrationService -VM $vm -Name 'Guest Service Interface', 'Heartbeat', 'Key-Value Pair Exchange', 'Shutdown', 'Time Synchronization', 'VSS'
        Get-VMNetworkAdapter -VM $vm | Connect-VMNetworkAdapter -SwitchName $VSwitchName
        $vhdPath = "$($vm.Path)\Virtual Hard Disks\$($vm.Name).vhdx"
        if(Test-Path $vhdPath) {
            Remove-Item $vhdPath -Force
        }
        $vhd = New-VHD -Differencing -Path $vhdPath -ParentPath $BaseImage
        $bootDevice = Add-VMHardDiskDrive -VM $vm -Path $vhd.Path -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -Passthru
        Set-VMFirmware -VM $vm -BootOrder @($bootDevice)
        if($Start){
            Start-VM -VM $vm
        }
        if($Wait){
            Wait-VM -VM $vm -For Heartbeat
        }
    } catch {
        throw "Failed creating VM $_"
    }

    return $vm
}