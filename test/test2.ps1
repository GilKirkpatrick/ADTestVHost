$vm = Get-VM DC1
$rootDSE = Wait-ForADTestLdap -Vm $vm
$rootDSE
