#PowewerShell - Final Exam
#Student Name: James Albers
#Course #: ITNET-154-800
#Date: October 27, 2021
##########################################################

#Question #1
#No need to add scripts for this question
Get-NetIPConfiguration
Get-WmiObject Win32_ComputerSystem


#region Question #2
#submitted by James Albers
#date October 29, 2021
Get-ChildItem Env:\COMPUTERNAME
Test-Connection -ComputerName DC2,Client1 -Count 3 -Delay 2
Get-DnsServerZone
Get-DnsServerResourceRecord -ZoneName "ITNET-154.pri"
#endregion 


#region Question #3
#submitted by James Albers
#date October 29, 2021
# Add Windows feature from PowerShell
Add-WindowsFeature -IncludeManagementTools dhcp
netsh dhcp add securitygroups
Add-DhcpServerInDC
# Get rid of GUI notification
Set-ItemProperty `
	-Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 `
	-Name ConfigurationState
	-Value 2
# Create DHCP scope on DC-1
Add-DhcpServerv4Scope `
	-Name "192.168.20.0"
	-StartRange 192.168.20.240 `
	-EndRange 192.168.20.250 `
	-SubnetMask 255.255.255.0 `
	-ComputerName DC1 `
	-LeaseDuration 8:0:0:0 `
	-Verbose
# Configure DHCP scope options
Set-DhcpServerv4OptionValue `
	-ScopeId 192.168.20.0 `
	-ComputerName DC1.ITNET-154.pri `
	-DnsServer 192.168.20.101 `
	-DnsDomain ITNET-154.pri `
	-Router 192.168.20.1
	-Verbose
Get-DHCPServerv4Scope | FT
Get-DHCPServerv4Lease -ScopeId 192.168.20.0
#endregion

#region Question #4
#submitted by James Albers
#date October 30, 2021
# Create an OU called 'DAs'
New-ADOrganizationalUnit -Name DAs -Path "DC=ITNET-154, DC=pri"
# Create DomainAdmin1, DomainAdmin20
New-ADUser `
	-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
	-Name "DomainAdmin1" `
	-Enabled $true `
	-Path "CN=Users, DC=ITNET-154, DC=pri" `
	-SamAccountName DomainAdmin1 `
	-UserPrincipalName ("DomainAdmin1@ITNET-154.pri)

New-ADUser `
	-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
	-Name "DomainAdmin20" `
	-Enabled $true `
	-Path "CN=Users, DC=ITNET-154, DC=pri" `
	-SamAccountName DomainAdmin20 `
	-UserPrincipalName ("DomainAdmin20@ITNET-154.pri")

# Add DomainAdmin1 and DomainAdmin20 to Domain Admins group
Add-ADGroupMember -Identity 'Domain Admins' -Members 'DomainAdmin1','DomainAdmin20'

#endregion

#region Question #5
#submitted by
#date

#endregion

#region Question #6 
#submitted by
#date

#endregion

#region Question #7 
#submitted by
#date

#endregion

#region Question #8
#submitted by
#date

#endregion

#region Question #9
#submitted by
#date

#endregion

#region Question #10
#submitted by
#date

#endregion 
