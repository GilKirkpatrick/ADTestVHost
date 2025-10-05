# Sysprep command .\sysprep /mode:vm /oobe /generalize /unattend:c:\windows\system32\sysprep\unattend.xml /shutdown
# Note on passing parameters to Jobs, ThreadJobs, and Invoke-Command:
# When start a job or invoke a command on another maching (VM or otherwise), PowerShell starts an entirely new PowerShell environment to run the commands in.
# The new environment doesn't share any context with the existing one (other than say the file system). Global variables, script variables, loaded modules, etc. don't
# exist in the new context. And when you use Invoke-Command on a VM or on a remote machine, the commands and modules you use might not even exsit there.
# The only context sharing is through the parameter list, or through the $using prefix, which only appears to work for local variables.
# Provide details on name formatting
# Set/Get-ADTestParameters needs to reset after change to file
# Gen1 vs. Gen2
# Differencing disk vs. copies
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon set to 0
# Install DC features in Initialize-ADTestDC, not in Initialize-ADTestServer
# Make gateway, dns setable in Initialize-ADTestServer
# implement multi-domain forest support


# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Get-ADTestParameters {
#    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
#    }
    if($null -eq $global:_ADTestParameters)
    {
        Set-ADTestParameters
    }
    # Simply returning the object returns a reference, which means the parameters can be changed... Sadly Clone()
    # isn't defined for PSObjects.
    return $global:_ADTestParameters
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Set-ADTestParameters {
    [CmdletBinding()]
    Param(
        [Parameter()][String]$ConfigPath = (Join-Path -Path (Split-Path $script:MyInvocation.MyCommand.Path) -ChildPath 'DefaultDomainConfig.json')
    )
    try {
        Write-Verbose "Reading default configuration from $ConfigPath"
        $global:_ADTestParameters = Get-Content $ConfigPath | ConvertFrom-Json
    }
    catch {
        Write-Error "Error reading settings from $ConfigPath."
        Throw $_
    }
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function New-ADTestDomain {
    [CmdletBinding()]
    Param(
        [Parameter()][int]$DCCount = 1,
        [Parameter()][String]$DomainName = (Get-ADTestParameters).DomainName,
        [Parameter()][String]$DCNamePattern = (Get-ADTestParameters).DCNamePattern,
        [Parameter()][String]$IPAddressPattern = (Get-ADTestParameters).IPAddressPattern,
        [Parameter()][String][ValidateSet('Win2003','Win2008','Win2008R2','Win2012','Win2012R2','WinThreshold','Default')]$ForestMode = (Get-ADTestParameters).ForestMode,
        [Parameter()][String][ValidateSet('Win2003','Win2008','Win2008R2','Win2012','Win2012R2','WinThreshold','Default')]$DomainMode = (Get-ADTestParameters).DomainMode,
        [Parameter()][String]$PwdString = (Get-ADTestParameters).PwdString,
        [Parameter()][String[]]$ModulesToCopy = (Get-ADTestParameters).ModulesToCopy,
        [Parameter()][String[]]$FeaturesToInstall = (Get-ADTestParameters).FeaturesToInstall,
        [Parameter()][Hashtable]$FilesToCopy = (Get-ADTestParameters).FilesToCopy,
        [Parameter()][String[]]$CommandsToRun = (Get-ADTestParameters).CommandsToRun,
        [Parameter()][String]$VSwitchName = (Get-ADTestParameters).VSwitchName,
        [Parameter()][String]$BaseImagePath = (Get-ADTestParameters).BaseImagePath,
        [Parameter()][String]$ParentDomain,
        [Parameter()][String]$ParentDns,
        [Parameter()][Switch]$Wait
    )

    # Create the virtual switch if it doesn't exist already
    if ($null -eq (Get-VMSwitch -Name $VSwitchName -ErrorAction Ignore)) {
        [void](New-VMSwitch -Name $VSwitchName -SwitchType Internal -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent))
    }

    # Define the DNS resolver for the 1st root DC in the domain
    if([String]::IsNullOrEmpty($ParentDomain)){
        $dnsAddress = '127.0.0.1'
    }
    else {
        if([String]::IsNullOrEmpty($ParentDns)){
            Throw "You must specify -ParentDns for the -ParentDomain"
        }
        else {
            $dnsAddress = $ParentDns
        }
    }
    $jobs= @()
    Write-Progress -Activity 'Provisioning servers' -CurrentOperation 'Starting background tasks' -Status 'Running' -PercentComplete 0 -Id 0
    for ($dcNumber = 0; $dcNumber -lt $DCCount; $dcNumber++) {
        $vmName = $DCNamePattern -f ($dcNumber + 1) # +1 so that the name corresponds to the IP address
        $ipAddress = $IPAddressPattern -f ($dcNumber + 1)

        Write-Progress -Activity 'Provisioning servers' -CurrentOperation 'Starting task $vmName' -Status 'Running' -PercentComplete (($dcNummber * 100) / $DCCount) -Id 0
        $jobs += Start-ThreadJob -Name $vmName -ArgumentList ($vmName, $BaseImagePath, $VSwitchName, ($dcNumber -eq 0), $ipAddress, $dnsAddress, $DomainName, $ForestMode, $DomainMode, $ParentDomain) -ScriptBlock {
            Param($VMName, $BaseImagePath, $VSwitchName, $IsFirstDC, $IPAddress, $DNSAddress, $DomainName, $ForestMode, $DomainMode, $ParentDomain)

            $vm = New-ADTestServer -VMName $VMName -VSwitchName $VSwitchName -BaseImagePath $BaseImagePath -Start -Wait
            if($IsFirstDC){
                Initialize-ADTestServer -Vm $vm -IPAddress $IPAddress -DNSAddress $DNSAddress -InstallADFeatures
                Initialize-ADTestFirstDC -Vm $vm -DomainName $DomainName -ForestMode $ForestMode -DomainMode $DomainMode -ParentDomain $ParentDomain
            }
            else {
                Initialize-ADTestServer -Vm $vm -IPAddress $IPAddress -DNSAddress $DNSAddress -DomainName $DomainName -InstallADFeatures
                Initialize-ADTestSubsequentDC -Vm $vm -DomainName $DomainName
            }
        }

        if($dcNumber -eq 0){
            $dnsAddress = $ipAddress # Use the IP of the first DC as the DNS address for subsequent DCs
        }
    }

    if($Wait){
        # Sit in a loop and poll the Progress channel of each job. Exit when all jobs are complete
        $runningStates = @($null, 'Running', 'AtBreakpoint', 'NotStarted', 'Stopping', 'Suspended')
        do {
            $jobsRunning = $false
            foreach ($job in $jobs){
                if($runningStates.Contains($job.State)){
                    $jobsRunning = $true
                }
                Start-Sleep -Seconds 1
#                foreach($progress in $job.Progress){
#                    Write-Progress @{
#                        Activity = $progress.Activity;
#                        CurrentOperation = $progress.CurrentOperation;
#                        Status = $progress.Status;
#                        PercentComplete = $progress.PercentComplete;
#                        Id = $progress.Id;
#                   }
#              }
            }
        } while($jobsRunning)
    }
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Initialize-ADTestFirstDC {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$True)]$Vm,
        [Parameter()][String]$DomainName = (Get-ADTestParameters).DomainName,
        [Parameter()][String]$ParentDomain = (Get-ADTestParameters).ParentDomain,
        [Parameter()][String][ValidateSet('Win2003','Win2008','Win2008R2','Win2012','Win2012R2','WinThreshold','Default')]$ForestMode = (Get-ADTestParameters).ForestMode,
        [Parameter()][String][ValidateSet('Win2003','Win2008','Win2008R2','Win2012','Win2012R2','WinThreshold','Default')]$DomainMode = (Get-ADTestParameters).DomainMode
    )
    try {
        Write-Verbose "Creating domain $DomainName with machine name $($Vm.Name), parent domain $ParentDomain, forest mode $ForestMode, domain mode $DomainMode"

        $pss = New-ADTestServerSession -Vm $Vm
        Invoke-Command -Session $pss -ArgumentList ($DomainName, $ParentDomain, $ForestMode, $DomainMode, (Get-ADTestSecurePassword)) -ScriptBlock {
            Param($DomainName, $ParentDomain, $ForestMode, $DomainMode, $SecurePwd)
            if([String]::IsNullOrEmpty($ParentDomain)){
                [void](Install-ADDSForest -SkipPreChecks -SafeModeAdministratorPassword $SecurePwd -DomainName $DomainName -ForestMode $ForestMode -DomainMode $DomainMode -InstallDns -NoDnsOnNetwork -Force)
            }
            else {
                $cred = New-Object System.Management.Automation.PSCredential "$ParentDomain\Administrator", $securePwd
                [void](Install-ADDSDomain -SkipPreChecks -SafeModeAdministratorPassword $SecurePwd -NewDomainName ($DomainName -split '\.')[0] -ParentDomain $ParentDomain -Credential $cred -DomainMode $DomainMode -InstallDns -Force)
            }
        }
    }
    catch {
        Throw "From Initialize-ADTestFirstDC: $_"
    }
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Initialize-ADTestSubsequentDC {
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm,
        [Parameter(Position=1)][String]$DomainName = (Get-ADTestParameters).DomainName
    )

    Write-Verbose "Promoting $($Vm.Name) as a DC in $DomainName"
    try {
        $securePwd = Get-ADTestSecurePassword
        $cred = New-Object System.Management.Automation.PSCredential ".\Administrator", $securePwd # Have to use .\Administrator because the machine is a domain member now
        Invoke-Command -VMId $Vm.Id -Credential $cred -ArgumentList ($DomainName, $securePwd) -ScriptBlock {
            Param($DomainName, $SecurePwd)

            $domainCred = New-Object System.Management.Automation.PSCredential "$DomainName\Administrator", $SecurePwd
            [void](Install-ADDSDomainController -SafeModeAdministratorPassword $SecurePwd -DomainName $DomainName -Credential $domainCred -InstallDns -Force)
        }
    }
    catch {
        Throw "From Initialize-ADTestSubsequentDC dcpromo: $_"
    }
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Get-ADTestSecurePassword {
    [CmdletBinding()]
    Param(
        [Parameter()][String]$PwdString = (Get-ADTestParameters).PwdString
    )
    return ConvertTo-SecureString $PwdString -AsPlainText -Force
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function New-ADTestServerSession {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm
    )

    Write-Verbose "Creating PowerShell session on VM $($Vm.Name)"
    $cred = New-Object System.Management.Automation.PSCredential "Administrator", (Get-ADTestSecurePassword)

    return New-PSSession -VMId $Vm.Id -Credential $cred
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Set-ADTestServerNetworking {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm,
        [Parameter(Mandatory=$True, Position=1)][String]$IPAddress,
        [Parameter(Mandatory=$True, Position=2)][String]$DNSAddress
    )
    Write-Verbose "Set networking configuration for $($Vm.Name) IP: $IPAddress DNS: $DNSAddress"

    $pss = New-ADTestServerSession -Vm $Vm
    Invoke-Command -Session $pss -ArgumentList ($IPAddress, $DNSAddress) -ScriptBlock {
        Param($IPAddress, $DNSAddress)

        $VerbosePreference = $using:VerbosePreference

        # Configure IP and DNS of the first Ethernet adapter
        $iface = (Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match "^Ethernet.*" } | Select-Object -First 1)
        [void]($iface | New-NetIPAddress -IPAddress $IPAddress -PrefixLength 16 -Verbose:([bool]$PSBoundParameters["Verbose"].IsPresent))
        [void]($iface | Set-DnsClientServerAddress -ServerAddresses @($DNSAddress) -Verbose:([bool]$PSBoundParameters["Verbose"].IsPresent))

        # Disable IPv6
        Disable-NetAdapterBinding -Name $iface.InterfaceAlias -ComponentID ms_tcpip6
    }
    Remove-PSSession $pss
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Install-ADTestServerFeatures {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm,
        [Parameter()][String[]]$FeaturesToInstall = (Get-ADTestParameters).FeaturesToInstall
    )
    Write-Verbose "Install Windows features for $($Vm.Name) $($FeaturesToInstall -join ',')"

    $pss = New-ADTestServerSession -Vm $Vm
    Invoke-Command -Session $pss -ArgumentList ($FeaturesToInstall) -ScriptBlock {
        Param($FeaturesToInstall)

        $VerbosePreference = $using:VerbosePreference

        # Disable auto-startup of Server Mangler because it is annoying
        [void](Get-ScheduledTask -TaskName 'ServerManager' | Disable-ScheduledTask)

        # Install additional configured features
        if($null -ne $FeaturesToInstall -and $FeaturesToInstall.Count -gt 0){
            [void](Install-WindowsFeature -Name $FeaturesToInstall -Verbose:([bool]$PSBoundParameters["Verbose"].IsPresent))
        }
    }
    Remove-PSSession $pss
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Copy-ADTestServerFiles {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm,
        [Parameter(Position=0)][Hashtable]$FilesToCopy = (Get-ADTestParameters).FilesToCopy
    )
    Write-Verbose "Copy files for $($Vm.Name)"
    if($FilesToCopy.Count -gt 0){
        $TargetFolderBase = 'C:\ProgramData\ADTestVHost'
        Copy-ADTestServerFilesRecursive -Vm $Vm -FilesToCopy $FilesToCopy -TargetFolderBase $TargetFolderBase
    }
}

Function Copy-ADTestServerFilesRecursive {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm,
        [Parameter(Mandatory=$True)][Hashtable]$FilesToCopy,
        [Parameter(Mandatory=$True)][String]$TargetFolderBase
    )

    $FilesToCopy.GetEnumerator().ForEach({
        if(Test-Path -Path $_.Name -PathType Container){ # If source is a folder, assume the target is a folder and recurse over the source's children
            if(-not [String]::IsNullOrEmpty($_.Value)){
                $TargetFolderBase += "\$($_.Value)"
            }
            else {
                $TargetFolderBase += "\$(Split-Path $_.Name -Leaf)"
            }
            (Get-ChildItem $_.Name).ForEach({
                $FileToCopy = @{}
                $FileToCopy.Add($_.FullName, $_.Value)
                Copy-ADTestServerFilesRecursive -Vm $Vm -FilesToCopy $FileToCopy -TargetFolderBase $TargetFolderBase
            })
        }
        elseif(Test-Path -Path $_.Name -PathType Leaf) {
            $sourcePath = (Get-Item $_.Name).FullName
            if(-not [String]::IsNullOrEmpty($_.Value)){
                $TargetFolderBase += "\$($_.Value)"
            }
            $destPath = "$TargetFolderBase\$(Split-Path $sourcePath -Leaf)"
            Write-Verbose "Copy from $sourcePath to $destPath"
            Copy-VMFile -Name $vm.Name -SourcePath $sourcePath -DestinationPath $destPath -FileSource Host -CreateFullPath
        }
        else {
            # Source path is not a file or folder
        }
    })
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Copy-ADTestServerModules {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm,
        [Parameter(Position=0)][String[]]$ModulesToCopy = (Get-ADTestParameters).ModulesToCopy
    )
    Write-Verbose "Copy PowerShell modules for $($Vm.Name) $($ModulesToInstall -join ',')"

    # Create a file archive containing all the folders to copy. This is really just to simplify the use of Copy-VMFile
    $modulesArchive = 'C:\Users\Administrator\Documents\WindowsPowerShell\Modules\PowerShell.zip' # Target in guest
    if($ModulesToCopy.Count -gt 0){
        $folders = @()
        $ModulesToCopy.ForEach({
            $folders += (Get-Module -ListAvailable $_).ModuleBase
        })
        $tempFilename = [System.IO.Path]::GetTempFileName() -replace '\.tmp', '.zip'
        Compress-Archive -Path $folders -DestinationPath $tempFilename -Force -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)

        Copy-VMFile -VM $Vm -SourcePath $tempFilename -FileSource Host -DestinationPath $modulesArchive -CreateFullPath -Force -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
    }

    $pss = New-ADTestServerSession -Vm $Vm
    Invoke-Command -Session $pss -ArgumentList ($ModulesToCopy, $modulesArchive) -ScriptBlock {
        Param($ModulesToCopy, $ModulesArchive)

        $VerbosePreference = $using:VerbosePreference

        # Allow unsigned PowerShell modules
        # Should change to AllSigned, or import code signing cert intro Trusted Publishers and Trusted Root CAs
        # https://community.spiceworks.com/how_to/153255-windows-10-signing-a-powershell-script-with-a-self-signed-certificate
        Set-ExecutionPolicy Bypass -Scope LocalMachine

        # Set PSModulePath for the current session and permanently for the current user
        # Not needed if we put the modules in C:\Users\Administrator\Documents\WindowsPowerShell\Modules
        # $env:PSModulePath = "$(Split-Path -Path $using:Environment.ModulesArchive -Parent);$env:PSModulePath"
        # [System.Environment]::SetEnvironmentVariable('PSModulePath', $env:PSModulePath, 'Machine')
        if($null -ne $ModulesToCopy -and $ModulesToCopy.Count -gt 0){
            # Expand the archive of PowerShell commands
            Expand-Archive -Path $ModulesArchive -DestinationPath (Split-Path -Path $ModulesArchive -Parent) -Verbose:$Verbose
            # Import the modules we copied.
            Import-Module $ModulesToCopy -Verbose:$Verbose
        }
    }
    Remove-PSSession $pss
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Invoke-ADTestServerCommands {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]$Vm,
        [Parameter(Position=1)][String[]]$CommandsToRun = (Get-ADTestParameters).CommandsToRun
    )
    Write-Verbose "Invoke commands for $($Vm.Name) $($CommandsToRun -join ";")"

    if($CommandsToRun.Count -gt 0){
        $pss = New-ADTestServerSession -Vm $Vm
        $CommandsToRun.ForEach({
            Invoke-Command -Session $pss -ScriptBlock ([ScriptBlock]::Create($_))
        })
        Remove-PSSession $pss
    }
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Initialize-ADTestServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]$Vm,
        [Parameter(Mandatory=$True, Position=1)][String]$IPAddress,
        [Parameter(Mandatory=$True, Position=2)][String]$DNSAddress,
        [Parameter()][String[]]$FeaturesToInstall = (Get-ADTestParameters).FeaturesToInstall,
        [Parameter()][String[]]$ModulesToCopy = (Get-ADTestParameters).ModulesToCopy,
        [Parameter()][Hashtable]$FilesToCopy = (Get-ADTestParameters).FilesToCopy,
        [Parameter()][String[]]$CommandsToRun = (Get-ADTestParameters).CommandsTorRun,
        [Parameter()][Switch]$InstallADFeatures,
        [Parameter()][String]$DomainName
    )

    Write-Verbose "Configuring server $($Vm.Name) at $IPAddress"

    Write-Progress -Activity "Configuring server" -PercentComplete 0 -CurrentOperation "Configuring networking"
    Set-ADTestServerNetworking -Vm $Vm -IPAddress $IPAddress -DNSAddress $DNSAddress

    Write-Progress -Activity "Configuring server" -PercentComplete 20 -CurrentOperation "Installing Windows features"
    if($InstallADFeatures){
        # Install AD components
        [void](Install-ADTestServerFeatures -Vm $Vm -FeaturesToInstall @('AD-Domain-Services', 'RSAT-ADDS') -Verbose:([bool]$PSBoundParameters["Verbose"].IsPresent))
    }
    Install-ADTestServerFeatures -Vm $Vm -FeaturesToInstall $FeaturesToInstall

    Write-Progress -Activity "Configuring server" -PercentComplete 50 -CurrentOperation "Copying and installing additional PowerShell modules"
    Copy-ADTestServerModules -Vm $Vm -ModulesToCopy $ModulesToCopy

    # This is where to copy other files and applications that need to be installed
    Copy-ADTestServerFiles -Vm $Vm -FilesToCopy $FilesToCopy

    # This is where to invoke additional commands
    Invoke-ADTestServerCommands -Vm $Vm -CommandsToRun $CommandsToRun

    if(-not [String]::IsNullOrEmpty($DomainName)){
        Write-Progress -Activity "Configuring server" -PercentComplete 80 -CurrentOperation "Joining server to domain"
        Join-ADTestServer -Vm $Vm -DomainName $DomainName -ComputerName $vm.Name -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
    }
    else {
        Write-Progress -Activity "Configuring server" -PercentComplete 80 -CurrentOperation "Renaming computer"
        Rename-ADTestServer -Vm $Vm -ComputerName $vm.Name -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
    }

    return $vm
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Rename-ADTestServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm,
        [Parameter(Mandatory=$True, Position=1)][String]$ComputerName
    )

    $pss = New-ADTestServerSession -Vm $Vm

    Write-Verbose "Renaming computer to $($Vm.Name)"
    Write-Progress -Activity "Renaming computer to $($Vm.Name)"
    Invoke-Command -Session $pss -ArgumentList ($ComputerName, (Get-ADTestSecurePassword)) -ScriptBlock {
        Param($ComputerName, $SecurePwd)
        $cred = New-Object System.Management.Automation.PSCredential "Administrator", $SecurePwd
        Rename-Computer -LocalCredential $cred -NewName $ComputerName -Force -Restart
    }
    Remove-PSSession $pss

    Write-Verbose "Waiting for reboot after computer rename"
    Write-Progress -Activity 'Waiting for reboot'
    Wait-VM -VM $Vm -For Reboot
    Wait-VM -VM $Vm -For Heartbeat
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Join-ADTestServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]$Vm,
        [Parameter(Mandatory=$True, Position=1)][String]$DomainName,
        [Parameter(Mandatory=$True, Position=2)][String]$ComputerName
    )

    Write-Verbose "Joining computer to $DomainName and renaming it to $ComputerName"
    Write-Progress -Activity "Waiting for domain $DomainName to join computer $ComputerName"

    $pss = New-ADTestServerSession -Vm $Vm
    Invoke-Command -Session $pss -ArgumentList ($DomainName, $ComputerName, (Get-ADTestSecurePassword)) -ScriptBlock {
        Param($DomainName, $NewName, $SecurePwd)

        do {
            Write-Verbose "Waiting for DC to become available for $DomainName"
            $dc = Get-ADDomainController -Discover -DomainName $DomainName -Service PrimaryDC -ErrorAction Ignore
        } while(($null -eq $dc) -and $null -eq (Start-Sleep 10))

        $domainCred = New-Object System.Management.Automation.PSCredential "$DomainName\Administrator", $SecurePwd
        [void](Add-Computer -DomainName $DomainName -Credential $domainCred -NewName $NewName -Force -Restart)
    }
    Remove-PSSession $pss

    Write-Verbose "Waiting for reboot after computer join"
    Write-Progress -Activity 'Waiting for reboot'
    Wait-VM -VM $Vm -For Reboot
    Wait-VM -VM $Vm -For Heartbeat
}
# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function New-ADTestServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$VMName,
        [Parameter()][String]$BaseImagePath = (Get-ADTestParameters).BaseImagePath,
        [Parameter()][String]$VMPath = (Get-ADTestParameters).VMPath,
        [Parameter()][String]$VSwitchName = (Get-ADTestParameters).VSwitchName,
        [Parameter()][uint64]$Memory = (Get-ADTestParameters).VMMemory,
        [Parameter()][int]$ProcessorCount = (Get-ADTestParameters).VMProcessorCount,
        [Parameter()][Switch]$Start,
        [Parameter()][Switch]$Wait
    )

    Write-Verbose "Base image $BaseImagePath VMPath $VMPath"
    try {
        if ($null -ne (Get-VM -Name $VMName -ErrorAction Ignore)) {
            Throw "VM $VMName already exists"
        }
        Write-Verbose "Creating VM $VMName"
        $vm = New-VM -Name $VMName -MemoryStartupBytes $Memory -NoVHD -SwitchName $VSwitchName -Path $VMPath -Generation 2 -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
        Enable-VMIntegrationService -VM $vm -Name 'Guest Service Interface', 'Heartbeat', 'Key-Value Pair Exchange', 'Shutdown', 'Time Synchronization', 'VSS'
        Set-VM -VM $vm -ProcessorCount $ProcessorCount -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)

        Get-VMNetworkAdapter -VM $vm | Connect-VMNetworkAdapter -SwitchName $VSwitchName
        $vhdPath = "$($vm.Path)\Virtual Hard Disks\$($vm.Name).vhdx"
        if (Test-Path $vhdPath) {
            Remove-Item $vhdPath -Force
        }
        $vhd = New-VHD -Differencing -Path $vhdPath -ParentPath $BaseImagePath -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
        $bootDevice = Add-VMHardDiskDrive -VM $vm -Path $vhd.Path -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -Passthru -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
        [void](Set-VMFirmware -VM $vm -BootOrder @($bootDevice) -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent))

        $dataVhdPath = "$($vm.Path)\Virtual Hard Disks\$($vm.Name)-data.vhdx"
        if (Test-Path $dataVhdPath) {
            Remove-Item $dataVhdPath -Force
        }
        $dataVhd = New-VHD -Path $dataVhdPath -Dynamic -Size 40GB -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
        Add-VMHardDiskDrive -VM $vm -Path $dataVhd.Path -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 1 -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)

        if ($Start) {
            [void](Start-VM -VM $vm -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent))
        }
        if ($Wait) {
            Wait-VM -VM $vm -For Heartbeat -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
        }
    }
    catch {
        throw "Failed creating VM $_"
    }

    return $vm
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Get-ADTestDCNames {
    [CmdletBinding()]
    param()
    $regex = '^' + ([String](Get-ADTestParameters).DCNamePattern).Replace('{0}', '\d+') + '$'
    return (Get-VM | Where-Object {$_.Name -match $regex}).Name
    # Note that you should use the array result from this command with .ForEach rather than piping the result to ForEach-Object (%)
    # This ensures that an empty set (no matching names) is not processed
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Stop-ADTestDCs {
    [CmdletBinding()]
    param()

    Write-Verbose "Stopping all DCs matching $((Get-ADTestParameters).DCNamePattern)"
    (Get-ADTestDCNames).ForEach({
        [void](Stop-VM -Name $_ -Force -AsJob)
    })

    do {
        $stillRunning = $False
        Write-Verbose "Waiting for all DCs to stop"
        (Get-ADTestDCNames).ForEach({
            Write-Verbose "Status of VM $_ is $((Get-VM -Name $_).State)"
            if((Get-VM -Name $_).State -ne 'Off'){
                $stillRunning = $True
            }
        })
    } while($stillRunning -and ($null -eq (Start-Sleep 1)))
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Reset-ADTestDCs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, Position=0)][String]$SnapshotName,
        [Parameter()][Switch]$Start
    )
    Write-Verbose "Restoring all DCs to checkpoint $SnapshotName"
    (Get-ADTestDCNames).ForEach({
        Restore-VMSnapshot -VMName $_ -Name $SnapshotName -Confirm:$False
    })
    # Generally checkpoints are taken when DCs are stopped, but if not, starting them will yield a benign warning
    if($Start){
        Start-ADTestDCs
    }
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Start-ADTestDCs {
    [CmdletBinding()]
    param()
    Write-Verbose "Starting all DCs"
    (Get-ADTestDCNames).ForEach({
        Start-VM -Name $_
    })
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Checkpoint-ADTestDCs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][String]$SnapshotName
    )
    Write-Verbose "Checkpointing all DCs to checkpoint $SnapshotName"
    Stop-ADTestDCs -Verbose:([bool]$PSBoundParameters["Verbose"].IsPresent)
    Checkpoint-VM -Name (Get-ADTestDCNames) -SnapshotName $SnapshotName
    Start-ADTestDCs -Verbose:([bool]$PSBoundParameters["Verbose"].IsPresent)
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Remove-ADTestDCs {
    [CmdletBinding()]
    param()

    Write-Verbose "Removing all DCs matching $((Get-ADTestParameters).DCNamePattern)"
    Remove-ADTestServer -ServerNames (Get-ADTestDCNames) -Verbose:([bool]$PSBoundParameters["Verbose"].IsPresent)
}

# .EXTERNALHELP ADTestVHost.psm1-Help.xml
Function Remove-ADTestServer {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)][String[]]$ServerNames
    )

    Write-Verbose "Removing servers in $($ServerNames -join ',')"

    $ServerNames.ForEach({
        Stop-VM -Name $_ -TurnOff -Force
        Remove-VM -Name $_ -Force
        Write-Verbose "Removing files at $(Join-Path -Path (Get-ADTestParameters).VMPath -ChildPath $_)"
        Remove-Item (Join-Path -Path (Get-ADTestParameters).VMPath -ChildPath $_) -Recurse -Force
    })
}
