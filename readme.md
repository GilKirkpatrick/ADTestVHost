# ADTestVHost - PowerShell module for creating Active Directory test environments
## Introduction
ADTestVHost is a PowerShell module that provides commands to completely automate the creation of Active Directory test environments. You can, with a single command provision and configured a complete
Active Directory domain with multiple domain controllers, with no additional interaction. There are additional commands for provisioning and configuring individual servers, stopping and starting them
as a group, and creating and restoring group snapshots.

The VMs are provisioned from a sysprepped VHDX that you provide using either WS2016 or WS2019. WS2012R2 doesn't have the necessary hypervisor support.

## Use case
I find myself frequently needing to create fresh Active Directory environments with multiple domain controllers, using them for a short while, and then getting rid of them. This is quite different from creating one or two AD forests and caring for and feeding them over a long period of time. I want all of the machines to be in a known clean state, and I typically don't need much, if any, AD data. I also need the AD environments to run on isolated virtual networks, ideally with no
network connectivity to my production network (or to the internet).

This module is an evolution of scripts and programs I created years ago to buid workshop environments for the Active Directory Disaster Recovery Workshop.

## Requirements
1. Hyper-V running on Windows 10, Windows Server 2019, or Windows Server 2016.
2. The Hyper-V and ThreadJob PowerShell modules must be installed on the Hyper-V host system. You install the Hyper-V module either through the Windows Features Control Panel applet, or through PowerShell using Install-WindowsFeature @('Hyper-V-PowerShell').
3. You must provide a Sysprepped image for the module to provision VMs with. The PowerShell commands create VMs with differencing disks that are based on the disk image you provide. It's a good idea to mark this image as read-only.
  * The disk image must be a VHDX (not VHD) disk image containing a bootable installation of Windows Server 2016 or Windows Server 2019.
  * It must have been built as a Gen2 Hyper-V instance.
  * The Administrator password has to be the same as that in the pwdString field of the DefaultDomainConfig.json file.

## Installation
1. Either use Git to clone this repository, or download a .zip file containing all the files.
2. Place the following files in the *ADTestVHost* folder of a directory listed in your PSModulePath environment variable:
  * ADTestVHost.psm1
  * ADTestVHost.psd1
  * DefaultDomainConfig.json
  * The entire en-us folder containing the XML help files
3. Run Install-Module ADTestVHost from the PowerShell prompt.
4. Modify the DefaultDomainConfig.json file to suit your environment. In particular you need to:
  * Change the vmPath value to a folder where the module will create VM images.
  * Change the baseImagePath value to a .VHDX file as described in the Requirements section.
  * Change the pwdString value to the cleartext password for the Administrator account used in your .VHDX.

## Overview of commands
*Get-ADTestParameters* retrieves the current default parameters for the AD environments you create. *Set-ADTestParameters* set the default parameters from a .JSON file you specify.

*New-ADTestDomain* creates a new domain with 1 or more domain controllers. It uses the values provided by Get-ADTestParameters, each of which can be overridden with command-line parameters.

*New-ADTestServer* provisions a new VM using the default .VHDX image. You can override the location of the VM files, the base image path, the amount of memory, and the Hyper-V network switch name with command-line parameters. The -Start switch will start the VM, and the -Wait switch will wait till the Sysprep Specialize and OOBE phases complete.

*Initialize-ADTestServer* initializes a VM created by *New-ADTestServer* by configuring the network adapter, renaming the computer to be the same as the VM name, installing Windows features, adding PowerShell modules from the host environment, and optionally joing the machine to an existing domain.

*Checkpoint-ADTestDCs* stops all the DCs (not all servers) in the test environment, takes a snapshot, and restarts the machines.

*Reset-ADTestDCs* applies the snapshot you specify to all of the DCs in the test environment.

*Remove-ADTestDCs* stops all the DCs in the environment, and deletes all the files associated with the VMs.

## Some examples
## Known issues
* The progress reporting for New-ADTestDomain is somewhat incomplete and provides some unnecessary detail.
* The -Verbose switch doesn't provide verbose details from the VMs themselves, just what executes on the Hyper-V host.
* After changing the DefaultDomainConfig.json file, you neet run Set-ADTestParameters to make changes take effect.
* No support for .VHD files or Gen1 VMs.
* The commandsToRun value in the DefaultDomainConfig.json file is not processed.

## Changelog
### Version 1.1 22 April 2020
1. Added ThreadJob and Hyper-V to the list of required modules
2. Added -Wait switch to New-ADTestDomain that will provide progress information as VMs are being provisioned and configured
3. Refactored quite a few functions to support #2
4. Exposed VSwitchName and BaseImagePath as parameters to New-ADTestDomain so that you can override the default configuration
5. Added -DomainName switch to Initialize-ADTestServer to allow creation of domain-joined machines that are not DCs
6. Added -FeaturesToInstall string[] and -ModulesToCopy string[] parameters to Intialize-ADTestServer to allow overriding of default configuration values
7. Fixed bugs in Stop-ADTestDCs and Remove-ADTestDCs
8. Move the machine renaming process to Initialize-ADTestServer. It renames the computer to be the same as the VM name
9. Added the beginnings of PowerShell help
