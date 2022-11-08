function Invoke-BlockCanaries ()
{
<#
    .SYNOPSIS
        Helper to Block All Known Canary IPS .      
    .EXAMPLE
        PS C:\> Invoke-BlockCanaries -InputFile ips.txt
#>
	[CmdletBinding()]

param (
$ranges = @("52.18.63.80", "52.18.63.80", "52.18.63.80", "205.251.196.97", "205.251.198.164", "205.251.193.123", "205.251.195.174", "172.253.63.26", "142.250.27.26", "142.250.153.27", "209.85.202.26", "64.233.184.27", "54.155.229.124", "52.204.60.219", "52.204.60.219", "52.204.60.219", "18.206.31.94", "18.206.31.94", "18.206.31.94", "52.31.39.52", "52.31.39.52", "52.31.39.52", "52.45.123.26", "52.45.123.26", "52.45.123.26", "52.31.39.52", "205.251.197.152", "205.251.199.151", "205.251.193.232", "205.251.194.96"),
$description = "Block All Known Canary IP Addresses"
)

try {
    $firewallRule = Get-NetFirewallRule -DisplayName $description -ErrorAction Stop;
        Write-Host -ForegroundColor Red "Firewall Rule Already Exist to Block All Known Canary IPS"
}
catch {
    if(-Not $firewallRule) {
        New-NetFirewallRule -DisplayName $description -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress $ranges
        Write-Host -ForegroundColor Green "Firewall Rule to Block Canary IP Addresses Succesffully Created" }
    }
}