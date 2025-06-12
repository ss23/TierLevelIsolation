Set-StrictMode -Version 3.0

# Load our helpers
. ./TierLevelHelpers.ps1 -Force

# The path to store the configuration file for tiering management. This is stored in SYSVOL to ensure it is accessible to any servers that need to run the maintenance scripts and can easily be recovered in a DR senario.
$DomainDNS = (Get-ADDomain).DNSRoot
$ConfigFile = "\\$DomainDNS\SYSVOL\$DomainDNS\scripts\TierLevelIsolation.json"
$DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName

if (![System.IO.File]::Exists($ConfigFile)) {
    Write-Log "Configuration file not found. Are you sure the install process completed succesfully?" -Severity Error
    throw
}

$Config = [TierLevelConfiguration](Get-Content $ConfigFile | ConvertFrom-Json)

if ($Config.Version -ne ([TierLevelConfiguration]@{}).Version) {
    Write-Log "The configuration file is older than the version used in this script. This may cause problems. Please update your configuration file to the latest version" -Severity Warning
}

Write-Log "Tier Isolation management script has started" -Severity Debug

# We need to apply the Kerberos Authentication Policy to any users that are considerd Tier 0. This is the mechanism that prevents them authenticating to a non-Tier 0 computer
# Get the policy we'd like to apply
try {
    $KerberosAuthenticationPolicy = Get-ADAuthenticationPolicy -Identity $Config.KerberosAuthenticationPolicyName
} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Log "Could not get Kerberos Authentication Policy. Did you successfully completely the install?" -Severity Error
    throw
} catch {
    Write-Log "Unexpected error attempting to fetch Kerberos Authentication Policy" -Severity Error
    throw
}

# As we are adding users into the Protected Users group if they're not already there, we fetch the members now to use later
$oProtectedUsersGroup = Get-ADGroup -Identity "$((Get-ADDomain -Server $DomainDNS).DomainSID)-525" -Server $DomainDNS -Properties member

# Verify the OU exists
try {
    $users = Get-ADUser -SearchBase "$($Config.OUTier0Users),$($DomainDN)" -Filter * -Properties msDS-AssignedAuthNPolicy,memberOf,UserAccountControl -SearchScope Subtree -Server $DomainDNS
} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Log "Cannot enumerate user OU. Are you sure you ran the install script?" -Severity Error
    throw
}

# TODO: Rather than loop over all users, we can filter out users that have the policy assigned and in the Protected Users group earlier
# This is more useful the more tier 0 users you have

# For every user within tier 0, ensure they are configured properly
foreach ($user in $users) {
    if ($user.SID -like "*-500"){
        Write-Log "Built in Administrator (-500) is located in managed user OU. Skipping..." -Severity Warning
        continue
    }

    # Assign the policy if not already assigned
    if ($user.'msDS-AssignedAuthNPolicy' -ne $KerberosAuthenticationPolicy.DistinguishedName) {
        Write-Log "Adding Kerberos Authentication Policy on $user" -Severity Information
        Set-ADUser $user -AuthenticationPolicy $Config.KerberosAuthenticationPolicyName -Server $DomainDNS
    }

    # Put the user in the Protected Users group - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts
    if ($oProtectedUsersGroup.member -notcontains $user.DistinguishedName) {
        Add-ADGroupMember -Identity $oProtectedUsersGroup $user -Server $DomainDNS
        Write-Log "User $($user.DistinguishedName) is addeded to protected users" -Severity Information
    }
}

# Find users who are not in the tier 0 groups and remove their managed Kerberos Authentication Policy
# Note we don't remove the Protected Users group membership, as we can't determine whether it is expected the user will remain in there or not
$users = Get-ADUser -Filter "msDS-AssignedAuthNPolicy -eq '$($KerberosAuthenticationPolicy.DistinguishedName)'" -Properties DistinguishedName -Server $DomainDNS
foreach ($user in $users) {
    if ($user.DistinguishedName -match "$($Config.OUTier0Users),$($DomainDN)$") {
        # The user is in the tiered OU, so we can skip them
        continue
    }
    Set-ADUser $user -Clear msDS-AssignedAuthNPolicy
    Write-Log "Removing Kerberos Authentication Policy on $user" -Severity Information
}

# Next we manage computers
try {
    $Tier0ComputerGroup = Get-ADGroup -Identity $Config.Tier0ComputerGroup -Properties member
} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Log "Cannot find Tier 0 computer group. Are you sure you ran the install script?" -Severity Error
    throw
}

$computersInOU = Get-ADComputer -Filter * -SearchBase "$($Config.OUTier0Computers),$DomainDN" -Properties Name, DistinguishedName

# Remove any computers from the Tier 0 Computers group that aren't in the OU still
foreach ($computer in $Tier0ComputerGroup.member) {
    if ($computersInOU.DistinguishedName -contains $computer) {
        # Skipping computer that is in here and should be
        continue
    }

    Write-Log "Removing $computer from $Tier0ComputerGroup" -Severity Information
    # TODO: This can be optimised with a single call to `Remove-ADGroupMember`
    Remove-ADGroupMember -Identity $Tier0ComputerGroup -Members $computer -Confirm:$false
}

# Add any computers to the tier 0 computer group if they're not currently part of it
$GroupUpdateRequired = $false
foreach ($computer in $computersInOU) {
    if ($Tier0ComputerGroup.member -notcontains $computer.DistinguishedName) {
        $GroupUpdateRequired = $true
        $Tier0ComputerGroup.member += $computer.DistinguishedName
        Write-Log "Adding $computer to $Tier0ComputerGroup" -Severity Information
    }
}

if ($GroupUpdateRequired) {
    Set-ADGroup -Instance $Tier0ComputerGroup
    Write-Log "Tier 0 computers group updated" -Severity Debug
}
