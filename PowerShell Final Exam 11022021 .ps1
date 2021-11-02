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
#submitted by James Albers
#date November 1, 2021
# Employee, Workstations, and Member Servers OU creation
New-ADOrganizationalUnit -Name Employees -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Workstations -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name "Member Servers" -Path "DC=ITNET-154, DC=pri"
# Sub OU's for Employees and Workstations OU's 
New-ADOrganizationalUnit -Name Office -Path "OU=Employees, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Employees, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Office -Path "OU=Workstations, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Workstations, DC=ITNET-154, DC=pri"
# Display the OU's
Get-ADOrganizationalUnit -Filter * | FT
#endregion

#region Question #6 
#submitted by James Albers
#date November 1, 2021
# Create TempEmployees OU
New-ADOrganizationalUnit -Name TempEmployees -Path "DC=ITNET-154, DC=pri"
# Create 50 users, Worker1 to Worker50
1..50 | ForEach {
    $userName = "Worker$_"
    New-ADUser -AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
	-Name "$userName" `
	-Enabled $true `
	-Path "OU=TempEmployees,DC=ITNET-154,DC=pri" `
	-SamAccountName "$userName" `
	-UserPrincipalName ($userName + "@ITNET-154.pri")
}

#endregion

#region Question #7 
#submitted by James Albers
#date November 1, 2021
# Create an OU for global security groups
New-ADOrganizationalUnit -Name GG_OU -Path "DC=ITNET-154, DC=pri"
# Create new global security group GG_Factory
New-ADGroup `
    -Name "GG_Factory" `
    -SamAccountName GG_Factory `
    -GroupCategory Security `
    -GroupScope Global `
    -DisplayName "GG_Factory" `
    -Path "OU=GG_OU,DC=ITNET-154,DC=pri"
# Add Worker1 thru Worker5 to GG_Factory
1..5 | ForEach {
    $userName = "Worker$_"
    Add-ADGroupMember `
	-Identity 'GG_Factory' `
	-Members $userName
}

#endregion

#region Question #8
#submitted by James Albers
#date November 1, 2021
# Create a new global security group GG_Office
New-ADGroup `
    -Name "GG_Office" `
    -SamAccountName GG_Office `
    -GroupCategory Security `
    -GroupScope Global `
    -DisplayName "GG_Office" `
    -Path "OU=GG_OU,DC=ITNET-154,DC=pri"
# Add Worker6 thru Worker10 to GG_Office
6..10 | ForEach {
$userName = "Worker$_"
Add-ADGroupMember `
    -Identity 'GG_Office' `
    -Members $userName
}
#endregion

#region Question #9
#submitted by James Albers
#date November 1, 2021
# Variables for path
$factory = "OU=Factory,OU=Employees,DC=ITNET-154,DC=pri"
$office = "OU=Office,OU=Employees,DC=ITNET-154,DC=pri"
# Move Worker1 thru Worker5 to Factory OU
1..5 | ForEach {
Get-ADUser "Worker$_" | Move-ADObject -TargetPath $factory
}
# Move Worker6 thru Worker10 to Office OU
6..10 | ForEach {
Get-ADUser "Worker$_" | MoveADObject -TargetPath $office    
}

#endregion

#region Question #10
#submitted by James Albers
#date November 1, 2021
# Create a global security group GG_AllEmployees
New-ADGroup
-Name "GG_AllEmployees" `
-GroupCategory Security `
-DisplayName "GG_AllEmployees" `
-Path "OU=GG_OU,DC=ITNET-154,DC=pri"
# Nest global groups
Add-ADGroupMember -Identity 'GG_AllEmployees' -Members GG_Factory, GG_Office

#endregion 

#region Question #11
#submitted by James Albers
#date November 1, 2021
New-Item -Path "c:\" -Name "AllEmplys" -ItemType Directory -Force
New-SmbShare -Path "c:\AllEmplys" `
-Name AllEmplys `
-FullAccess "Domain Admins","GG_Factory","GG_Office"  
Get-SmbShareAccess -Name "AllEmplys"
Get-Acl -Path "c:\AllEmplys" | Format-List
#endregion 

#region Question #12
#submitted by James Albers
#date November 2, 2021
New-Item -Path "c:\AllEmplys" -Name "FactoryStuff" -ItemType Directory -Force

# *** Assign Read permissions to GG_Office ***
$acl = Get-Acl "c:\AllEmplys\FactoryStuff"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule `
("ITNET-154\GG_Office","Read","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($AccessRule)

# *** Assign R/W permissions to GG_Factory ***
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule `
("ITNET-154\GG_Factory","Write","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($AccessRule)

# *** Assign Full Control to Domain Admins ***
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule `
("ITNET-154\Domain Admins","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($AccessRule)

$acl | Set-Acl c:\AllEmplys\FactoryStuff
$acl | Format-List

#endregion 

#region Question #13
#submitted by James Albers
#date November 2, 2021
Get-ADUser  -Filter  *  -Properties Name, MemberOf | Out-gridview
#endregion 


