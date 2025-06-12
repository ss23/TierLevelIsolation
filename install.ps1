Set-StrictMode -Version 3.0

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy  -ErrorAction Stop
} 
catch {
    Write-Host "Failed to load the required Powerhsell module" -ForegroundColor Red
    Write-Host "validate the Active Directory and Group Policy Powershell modules are installed" -ForegroundColor Red
    exit
}

# Load our helpers
. ./TierLevelHelpers.ps1 -Force

Write-Host "Welcome to the Simplified Tier Level isolation setup script" -ForegroundColor Green

# The path to store the configuration file for tiering management. This is stored in SYSVOL to ensure it is accessible to any servers that need to run the maintenance scripts and can easily be recovered in a DR senario.
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
$ConfigFile = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts\TierLevelIsolation.json"
$CurrentDomainDN = (Get-ADDomain).DistinguishedName
$GCDC = (Get-ADDomainController -Discover -Service GlobalCatalog -NextClosestSite ).HostName[0]

[TierLevelConfiguration] $Config = [TierLevelConfiguration]@{}

# Check whether we're already installed. If so, we want to tell the user so they can abort.
if ([System.IO.File]::Exists($ConfigFile)) {
    # If there was a configuration file already set, lets load it now
    $Config = [TierLevelConfiguration](Get-Content $ConfigFile | ConvertFrom-Json)

    # A version of -1 indicates the base, unmodified configuration file, which is expected if the user is overriding the default configuration
    # Anything else is unexpected
    if ($Config.Version -ne -1) {
        Write-Host "A configuration file already exists. If you are not expecting this, it is likely you have already run this installer and you should abort now." -ForegroundColor Yellow
        $strReadHost = Read-Host "Do you want to continue y/[n]"
        if ($strReadHost -eq '') { $strReadHost = "n" }
        if ($strReadHost -notlike "y*") {
            Write-Host "aborting" -ForegroundColor Yellow
            return
        }

        if ($Config.Version -ne ([TierLevelConfiguration]@{}).Version) {
            Write-Host "The configuration file is older than the version used in this script. The new version will be written when this script completes" -ForegroundColor Yellow
        }
    }
}

# Ensure that the version is updated to the version of this installer script
$Config.Version = ([TierLevelConfiguration]@{}).Version

# To run the installer, we must be a member of Domain Adminstrators (SID ending -512)
if (![System.Security.Principal.WindowsIdentity]::GetCurrent().Groups -like "*-512") {
    Write-Host "You are not in the Domain Admins group. It is likely this script will fail" -ForegroundColor Yellow
    $strReadHost = Read-Host "Do you want to continue y/[n]"
    if ($strReadHost -eq '') { $strReadHost = "n" }
    if ($strReadHost -notlike "y*") {
        Write-Host "aborting" -ForegroundColor Yellow
        return
    }
}

# Validate and create OUs
New-TierLevelOU -OUPath $Config.OUTier0Users -DomainDNS $GCDC
New-TierLevelOU -OUPath $Config.OUTier0Computers -DomainDNS $GCDC
New-TierLevelOU -OUPath $Config.OUTier0ServiceAccounts -DomainDNS $GCDC

try {
    Get-ADGroup -Identity $Config.Tier0ComputerGroup -Server $GCDC | Out-Null
    # If we don't throw from that, the group already existed
    Write-Host "The group $($config.Tier0ComputerGroup) was already created." -ForegroundColor Yellow
} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    # If we get here, the group was not present, which is expected at this stage
    New-ADGroup -Name $Config.Tier0ComputerGroup -GroupScope Universal -Description "Contains all Tier 0 member computers, and is used for the Kerberos Authentication Policy claim" -Server $GCDC -Path "$($Config.OUTier0Computers),$CurrentDomainDN"
}

# Set the adminCount flag on the group - https://techcommunity.microsoft.com/blog/askds/five-common-questions-about-adminsdholder-and-sdprop/396293
Get-ADGroup -Identity $Config.Tier0ComputerGroup -Server $GCDC | Set-ADObject -replace @{adminCount = 1 }
$Tier0ComputerGroup = Get-ADGroup -Identity $Config.Tier0ComputerGroup -Server $GCDC

try {
    Get-ADAuthenticationPolicy -Identity $Config.KerberosAuthenticationPolicyName | Out-Null
    Write-Host "Kerberos Authentication Policy $($Config.KerberosAuthenticationPolicyName) already exists. Please validate the policy manually." -ForegroundColor Yellow
} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    # If we get here, the policy does not already exist, which is expected

    # This policy allows User Sign On when the server is either in the Enterprise Domain Controllers, or the Tier 0 Computers group
    # Once the policy is created, it can be viewed in a more readable format through the Active Directory Administration Center
    $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)}) || (Member_of_any {SID($($Tier0ComputerGroup.SID))})))"
    New-ADAuthenticationPolicy -Name $Config.KerberosAuthenticationPolicyName `
        -Enforce `
        -UserAllowedToAuthenticateFrom $AllowToAutenticateFromSDDL `
        -ProtectedFromAccidentalDeletion $true `
        -Description "This policy aims to isolate Tier 0 systems to ensure the security and integrity of critical IT infrastructures. Users assigned this policy can only log in to computers that are members of the 'Enterprise Domain Controller' group or the 'Tier 0 Server'group. This ensures that only authorized users have access to the most sensitive systems within the organization."
}

# Write our configuration file now that installation is complete
$Config | ConvertTo-Json | Out-File $ConfigFile

Write-Host "Installation is complete. You should now configure GPOs to enable Claim Support and begin moving users to the Tiering OUs and Computers to the Tier 0 group" -ForegroundColor Green