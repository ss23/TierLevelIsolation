<#
Script Info

Author: Andreas Lucas [MSFT]
Download: https://github.com/Kili69/Tier0-User-Management

Disclaimer:
This sample script is not supported under any Microsoft standard support program or service. 
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
damages whatsoever (including, without limitation, damages for loss of business profits, business 
interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages
.Synopsis
    Managing of Tier 0 and Tier 1 computer groups

.DESCRIPTION
    This script add or remove computer objects if they are not located in specific Tier 0 or Tier 1 
    computer OU.
    The script allows multiple OU's for Tier 0 / 1
.OUTPUTS 
    The script does not produce any direct outputs.
.PARAMETER ConfigFile
    The full path to the configuration file. If this parameter is not provided, the script will search for the configuration in Active Directory or on the SYSVOL path.
.PARAMETER scope
    Defines the scope of the script. Possible values are:
        Tier-0: Only the Tier 0 user accounts will be managed.
        Tier-1: Only the Tier 1 user accounts will be managed.
        All-Tiers: Both Tier 0 and Tier 1 user accounts will be managed.
.NOTES
    Version 0.2.20241206
    Initial Version
    Version 0.2.20241220
        If a user is removed from a privileged group, the adminCount attribute will be removed from the user
        The script will check if the user is located in a service account OU. If the user is located in a service account OU, the user will not be removed from the privileged group
        

    All events written to the log file. Information, Warnings and error events are written to the eventlog
    All event IDs documented in EventID.md

#>
param(
    [Parameter (Mandatory = $false)]
    [string] $ConfigFile,
    [Parameter (Mandatory = $false)]
    [ValidateSet("Tier-0", "Tier-1", "All-Tiers")]
    $scope
)

#region functions
<#
.SYNOPSIS
    Write event to the event log and the debug log file
.DESCRIPTION
    This funtion will write all events to the log file. If the severity is debug the message will only be written to the debuig log file
    This function replaced the write-eventlog and write-host cmdlets in this script
.OUTPUTS
    None
.FUNCTIONALITY
    Write event to the log file and event log
.PARAMETER Message
    Is the message body of the event
.PARAMETER Severity
    Is the event severity. Supported severities are: Debug, Information, Warning and Error
.PARAMETER EventID
    Is the event ID logged in the application log
.EXAMPLE
    write-log -Message "My message" - Severity Information -EventID 0
        This will create a new log line in the debug log file, create a eventlog entry in the application log and writes the 
        message parameter to the console
#>
function Write-Log {
    param (
        # status message
        [Parameter(Mandatory = $true)]
        [string]$Message,
        #Severity of the message
        [Parameter (Mandatory = $true)]
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        $Severity,
        #Event ID
        [Parameter (Mandatory = $true)]
        [int]$EventID
    )
    #validate the event source TierLevelIsolation is registered in the application log. If the registration failes
    #the events will be written with the standard application event source to the event log. 
    try {   
        $eventLog = "Application"
        $source = "TierLevelIsolation"
        # Check if the source exists; if not, create it
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            [System.Diagnostics.EventLog]::CreateEventSource($source, $eventLog)
        }
    }
    catch {
        Add-Content -Path $LogFile -Value "$(Get-Date -Format o), Error, Can't register Event source"
        $source = "Application"
    }

    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format o), [$Severity],[$EventID], $Message"
    Add-Content -Path $LogFile -Value $LogLine 
    #If the severity is not debug write the even to the event log and format the output
    switch ($Severity) {
        'Error' { 
            Write-Host $Message -ForegroundColor Red
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Error -Message $Message -Category 0
        }
        'Warning' { 
            Write-Host $Message -ForegroundColor Yellow 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Warning -Message $Message -Category 0
        }
        'Information' { 
            Write-Host $Message 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Information -Message $Message -Category 0
        }
    }
}
<#
.SYNOPSIS
    Applied the Kerberos Authentication Policy to the users and add them to the protected users group
.DESCRIPTION
    This function applies the Kerberos Authentication policy to all users in the OU parameter and
    add the user to the protected users groups if the AddProtectedUsersGroup is true
.FUNCTIONALITY

.PARAMETER DomainDNS
    The domain DNS Name
.PARAMETER OrgUnits
    Is a array of OU distinguishednames of the Tier level users
.PARAMETER AddProtectedUsersGroup
    Is this parameter is true the user will be added to the protected users
.PARAMETER KerbAuthPolName
    Is the name of the Kerberos Authentication Policy
.OUTPUTS 
    $True if all users in the privilegd OU are marked as sensitive and the kerberos authentication policy is applied
    $False
#>
function Set-TierLevelIsolation{
    param(
        [Parameter (Mandatory = $true)]
        [string] $DomainDNS,
        [Parameter (Mandatory = $true)]
        [string[]]$OrgUnits,
        [Parameter (Mandatory = $false)]
        [bool]$AddProtectedUsersGroup = $false,
        [Parameter (Mandatory = $true)]
        [string]$KerbAuthPolName
    )
    $retval = $false
    try {
        $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
        #Validate the Kerboers Authentication policy exists. If not terminate the script with error code 0xA3. 
        $KerberosAuthenticationPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($KerbAuthPolName)'"
        if ($null -eq $KerberosAuthenticationPolicy){
            Write-Log -Message "Tier 0 Kerberos Authentication Policy '$KerberosPolicyName' not found on AD" -Severity Error -EventID 2101
            return $false
        }
        $oProtectedUsersGroup = Get-ADGroup -Identity "$((Get-ADDomain -Server $DomainDNS).DomainSID)-525" -Server $DomainDNS -Properties member
        foreach ($OU in $OrgUnits){
            if ($OU -like "*$DomainDN"){
                if ($null -eq (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OU'" -Server $DomainDNS)){
                    Write-Log -Message "The OU $OU doesn't exists in $DomainDNS" -Severity Warning -EventID 2102
                } else {
                    foreach ($user in (Get-ADUser -SearchBase $OU -Filter * -Properties msDS-AssignedAuthNPolicy,memberOf,UserAccountControl -SearchScope Subtree -Server $DomainDNS)){
                        if ($user.SID -like "*-500"){
                            Write-Log -Message "Built in Administrator (-500) is located in $OU" -Severity Warning -EventID 2103
                            #ignore the built-in administrator
                        } else {
                            #Kerberos Authentication Policy validation
                            if ($user.'msDS-AssignedAuthNPolicy' -ne $KerberosAuthenticationPolicy.DistinguishedName){
                                Write-Log "Adding Kerberos Authentication Policy $KerbAuthPolName on $User" -Severity Information -EventID 2104
                                Set-ADUser $user -AuthenticationPolicy $KerbAuthPolName -Server $DomainDNS
                            }
                            #User account control validation
                            if (($user.UserAccountControl -BAND 1048576) -ne 1048576){
                                Set-ADAccountControl -Identity $user -AccountNotDelegated $True -Server $DomainDNS
                                Write-Log -Message "Mark $($User.DistinguishedName) as sensitive and cannot be delegated" -Severity Information -EventID 2105
                            }
                            #Protected user group validation
                            if ($AddProtectedUsersGroup -and ($oProtectedUsersGroup.member -notcontains $user.Distiguishedname)){
                                Add-ADGroupMember -Identity $oProtectedUsersGroup $user -Server $DomainDNS
                                Write-Log "User $($user.Distiguishedname) is addeded to protected users in $Domain" -Severity Information -EventID 2106
                            }
                        }
                    }
                }
            }
        }
        $retval = $true
    }
    catch [Microsoft.ActiveDirectory.Management.ADException]{
        Write-Log "a access denied error occurs while changing $user attribute" -Severity Error -EventID 2107
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Log "Cannot enumerrate users" -Severity Error -EventID 2108
    }
    catch{
        Write-Log "A unexpected error occured $($error[0])" -Severity Error -EventID 2109
    } 
    return $retval  
}

<#
.SYNOPSIS
    Remove unexpected user to the privileged group 
.DESCRIPTION 
    Searches for users in privileged groups and remove those user if the are not 
    - in the correct OU
    - the built-In Administrator
.PARAMETER SID
    - is the SID of the AD group
.PARAMETER DomainDNSName
    -is the domain DNS name of the AD object
.PARAMETER PrivilegedOU
    -is a array of Distinguishednames to the privileged user OUs
.PARAMETER ServiceAccountPath
    -is a array of distinguishednames to the service account OU
.EXAMPLE
    validateAndRemoveUser -SID "S-1-5-<domain sid>-<group sid>" -DomainDNS contoso.com

#>
function validateAndRemoveUser{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        #The SID uof the group
        [Parameter (Mandatory = $true)]
        [string] $SID,
        #The DNS domain Name
        [Parameter (Mandatory = $true)]
        [string] $DomainDNSName,
        [Parameter(Mandatory = $true)]
        [string[]] $PrivilegedOU,
        [Parameter(Mandatory = $true)]
        [string[]] $ServiceAccountPath

    )
    $Group = Get-ADGroup -Identity $SID -Properties members,canonicalName -Server $DomainDNSName 
    #validate the SID exists
    if ($null -eq $Group){
        Write-Log "Can't validate $SID. This SID is not available" -Severity Warning -EventID 2200
        return
    }
    #walk through all members of the group and check this member is a valid user or group
    foreach ($Groupmember in $Group.members)
    {
        $member = Get-ADObject -Filter {DistinguishedName -eq $Groupmember} -Properties * -server "$($DomainDNSName):3268"
        switch ($member.ObjectClass){
            "user"{
                if (($member.ObjectSid.value   -notlike "*-500")                              -and ` #ignore if the member is Built-In Administrator
                    ($member.objectSid.value   -notlike "*-512")                              -and ` #ignoer if the member is Domain Admins group
                    ($member.ObjectSid.value   -notlike "*-518")                              -and ` #ignore if the member is Schema Admins
                    ($member.ObjectSid.Value   -notlike "*-519")                              -and ` #ignore if the member is Enterprise Admins
                    ($member.objectSid.Value   -notlike "*-520")                              -and ` #ignore if the member is Group Policy Creator
                    ($member.objectSid.Value   -notlike "*-522")                              -and ` #ignore if the member is cloneable domain controllers
                    ($member.objectSid.Value   -notlike "*-527")                              -and ` #ignore if the member is Enterprise Key Admins
                    ($member.objectClass       -ne "msDS-GroupManagedServiceAccount") #        -and ` #ignore if the member is a GMSA
#                    ($member.distinguishedName -notlike "*,$PrivilegedOUPath,*")              -and ` #ignore if the member is located in the Tier 0 user OU
#                    ($member.distinguishedName -notlike "*,$PrivilegedServiceAccountOUPath*") -and ` #ignore if the member is located in the service account OU
#                    ($excludeUser              -notlike "*$($member.DistinguishedName)*" )           #ignore if the member is in the exclude user list
                    ){
                        if (($PrivilegedOU | Where-Object {$member.DistinguishedName -like "*$_"} ).Count -eq 0){
                            #the user is not located in the privileged OU check the user is located in the service account OU
                            if (($ServiceAccountPath | Where-Object {$member.DistinguishedName -like "*$_"}).count -eq 0){
                                #The user is not located in the service account OU. Try to remove the user from the current group
                                try{
                                    Write-Log -Message "remove $member from $($Group.DistinguishedName)" -Severity Warning -EventID 2201
                                    Set-ADObject -Identity $Group -Remove @{member="$($member.DistinguishedName)"} -Server $DomainDNSName
                                    Set-ADUser -Identity $member -Remove @{adminCount=1} -Server $member.canonicalName.Split("/")[0]
                                }
                                catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
                                    Write-Log -Message "can't connect to AD-WebServices. $($member.DistinguishedName) is not remove from $($Group.DistinguishedName)" -Severity Error -EventID 2202
                                }
                                catch [Microsoft.ActiveDirectory.Management.ADException]{
                                    Write-Log -Message "Cannot remove $($member.DistinguishedName) from $($Error[0].CategoryInfo.TargetName) $($Error[0].Exception.Message)" -Severity Error -EventID 2203
                                }
                                catch{
                                    Write-Log -Message $Error[0].GetType().Name -Severity Error -EventID 2204
                                }
                            } else {
                                Write-Log -Message "The user $($member.DistinguishedName) is located in a Service account OU and will not be removed from the privileged groups $($Group.Distiguishedname)" -EventID 2205 -Severity Debug
                            }
                        } else {
                            Write-Log -Message "The user $($member.Distiguishedname) is member of a privileged user OU" -Severity Debug -EventID 2206
                        }
                    }
                }
            "group"{
                $MemberDomainDN = [regex]::Match($member.DistinguishedName,"DC=.*").value
                $MemberDNSroot = (Get-ADObject -Filter "ncName -eq '$MemberDomainDN'" -SearchBase (Get-ADForest).Partitionscontainer -Properties dnsRoot).dnsRoot
                validateAndRemoveUser -SID $member.ObjectSid.Value -DomainDNSName $MemberDNSroot -PrivilegedOU $PrivilegedOU -ServiceAccountPath $ServiceAccountPath
            }
        }
    }        
}

function ConvertTo-DistinguishedNames{
    param (
        [Parameter(Mandatory = $true)]
        [string[]] $DomainsDNS,
        [Parameter (Mandatory = $true)]
        [string[]] $DistinguishedNames
    )
    $FQDN = @()
    $DomainDN = @()
    
    try {
        foreach ($Domain in $DomainsDNS){
            $DomainDN += (Get-ADDomain -Server $Domain).DistinguishedName
        }        
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
        Write-Log -Message "Failed to contact $domain" -Severity Debug -EventID 2300
    }
    foreach ($DN in $DistinguishedNames){
        if ($DN -like "*,DC=*"){
            $FQDN += $DN
        } else {
            foreach ($DomDN in $DomainDN){
                $FQDN += "$DN,$DomDN"
            }
        }
    }
    return $FQDN
}
#endregion


##############################################################################################################################
# Main program starts here
##############################################################################################################################
#script Version 
$ScriptVersion = "0.2.20241220"

#region constantes
$config = $null
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
$DefaultConfigFile = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts\Tiering.config"
$ADconfigurationPath = "CN=Tier Level Isolation,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"

$PrivlegeDomainSid = @(
    "512", #Domain Admins
    "520", #Group Policy Creator Owner
    "522" #Cloneable Domain Controllers
#   "527" #Enterprise Key Admins
)
#endregion

#region Manage log file
[int]$MaxLogFileSize = 1048576 #Maximum size of the log file
$LogFile = "$($env:LOCALAPPDATA)\$($MyInvocation.MyCommand).log" #Name and path of the log file
#rename existing log files to *.sav if the currentlog file exceed the size of $MaxLogFileSize
if (Test-Path $LogFile) {
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize) {
        if (Test-Path "$LogFile.sav") {
            Remove-Item "$LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
}
#endregion
Write-Log -Message "Tier Isolation user management $Scope version $ScriptVersion started" -Severity Information -EventID 2000
#region read configuration
try{
    if ($ConfigFile -eq '') {
        Write-host "AD config lesen noch implementieren $ADconfigurationPath" -ForegroundColor Red -BackgroundColor DarkGray
        #last resort if the configfile paramter is not available and no configuration is stored in the AD. check for the dafault configuration file
        if ($null -eq $config){
            if ((Test-Path -Path $DefaultConfigFile)){
                Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 2003
                $config = Get-Content $DefaultConfigFile | ConvertFrom-Json            
            } else {
                Write-Log -Message "Can't find the configuration in $DefaultConfigFile or Active Directory" -Severity Error -EventID 2004
                return 0xe7
            }
        }
    }
    else {
        Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 2003
        $config = Get-Content $ConfigFile | ConvertFrom-Json 
    }
}
catch {
    Write-Log -Message "error reading configuration" -Severity Error -EventID 2005
    return 0x3E8
}
#if the paramter $scope is set, it will overwrite the saved configuration

if ($null -eq $scope ){
    $scope = $config.scope
} 
switch ($scope) {
    "Tier-0" { 
        if ($config.scope -eq "Tier-1"){
            Write-Log -Message "The scope paramter $scope does not match to the configuration scope $($config.scope) the script is terminated" -Severity Error -EventID 2006
            return 0x3E8
        } else {
            $config.Tier0UsersPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier0UsersPath
            $config.Tier0ServiceAccountPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier0ServiceAccountPath
            break
        }
    }
    "Tier-1"{
        if ($config.scope -eq "Tier-0"){
            Write-Log -Message "The scope paramter $scope does not match to the configuration scope $($config.scope) the script is terminated" -Severity Error -EventID 2006
            return 0x3E8
        } else {
            $config.Tier1UsersPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier1UsersPath
            $config.Tier1ServiceAccountPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier1ServiceAccountPath
            break
        }
    }
    Default {
        Write-Log -Message "Current scope is $scope" -Severity Debug -EventID 2006
        $config.Tier0UsersPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier0UsersPath
        $config.Tier0ServiceAccountPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier0ServiceAccountPath
        $config.Tier1UsersPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier1UsersPath
        break
    }
}
#endregion
$T0ProtectedUsers = $false
$T1ProtectedUsers = $false
switch ($config.ProtectedUsers) {
    {-contains "Tier-0"} { $T0ProtectedUsers = $true }
    {-contains "Tier-1"} { $T1ProtectedUsers = $true }
}

foreach ($Domain in $config.Domains){
    if ($scope -ne "Tier-1"){
        if ((Set-TierLevelIsolation -DomainDNS $Domain -OrgUnits $config.Tier0UsersPath -AddProtectedUsersGroup $T0ProtectedUsers -KerbAuthPolName $config.T0KerbAuthPolName)){
            Write-Log -Message "Tier 0 user isolated" -Severity Debug -EventID 2010
        } else{
            Write-Log -Message "Tier 0 user isolation failed" -Severity Debug -EventID 2011
        }
    } 
    if ($scope -ne "Tier-0") {
        if ((Set-TierLevelIsolation -DomainDNS $Domain -OrgUnits $config.Tier1UsersPath -AddProtectedUsersGroup $T1ProtectedUsers -KerbAuthPolName $config.T1KerbAuthPolName)){
            Write-Log -Message "Tier 1 user isolated" -Severity Debug -EventID 2012
        } else {
            Write-Log -Message "Tier 1 user isolation failed" -Severity Debug -EventID 2013
        }
    }
    if ($config.PrivilegedGroupsCleanUp){
        foreach ($relativeSid in $PrivlegeDomainSid) {
            validateAndRemoveUser -SID "$((Get-ADDomain -server $Domain).DomainSID)-$RelativeSid" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        }
        #Backup Operators
        validateAndRemoveUser -SID "S-1-5-32-551" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        #Print Operators
        validateAndRemoveUser -SID "S-1-5-32-550" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        #Server Operators
        validateAndRemoveUser -SID "S-1-5-32-549" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        #Server Operators
        validateAndRemoveUser -SID "S-1-5-32-548" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        #Administrators
        validateAndRemoveUser -SID "S-1-5-32-544" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
    }
}
if ($config.PrivilegedGroupsCleanUp){
    $forestDNS = (Get-ADDomain).Forest
    $forestSID = (Get-ADDomain -Server $forestDNS).DomainSID.Value
    Write-Log "searching for unexpected users in schema admins" -Severity Debug -EventID 2008
    validateAndRemoveUser -SID "$forestSID-518" -DomainDNSName $forestDNS -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
    Write-Log "searching for unexpteded users in enterprise admins" -Severity Debug -EventID 2009
    validateAndRemoveUser -SID "$forestSID-519" -DomainDNSName $forestDNS -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
}
