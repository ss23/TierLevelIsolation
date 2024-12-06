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
    None
.PARAMETER ConfigFile
    This is the full quaified path to the configuration file. If this parameter is empty, the script will
    search for the configuration in Active Directory or on the SYSVOL path
.PARAMETER scope
    defines which scope will be used. Possible scopes are:
    Tier-0 only the Tier 0 computer group will be managed
    Tier-1 only the Tier 1 computer group will be managed
    All-Tiers   the computer group for Tier 0 and Tier1 will be managed
.NOTES
    Version 0.2.20241206
    Initial Version

    Important events are writte to the application log
    EventID: 2000
        Severity: Information
        Message: The script is started
    EventID: 2001 
        Severity: Error
        Message: A error occured while reading config file
    EventID: 2002 
    Severity: Error
        Message: A Kerberos Authentication Policy is missing
    EventID: 2100
        Severity: Warning
        Message: A OU missing in the current domain
    EventID: 2101
        Severity: Warning
        Message: The built-in administrator account is loacted in the tier 0 users OU
    EventID: 2102
        Severity: Information  
        Message: A kerberos  authentication policy is added to a user 
    EventID: 2103
        Serverity: Information
        Message: The "This user is sensitive and cannot be delegated  is set to a user
    EventID: 2104 
        Serverity: Information 
        Message: A users is added users to the protected users group
    EventID: 2105
        Serverity: Error
        Message: A error occurs while removing a user from a privileged groups
    EventID: 2106 
        Serverity: Error 
        Message: A identitiy could not be found
    EventID: 2107 
        Serverity: Error
        Message: A general error occurs while applying the kerberos authentication policy to a user
    EventID: 2200
        Serverity: Error 
        Message: Invalid group sid 
    EventID: 2201 
        Serverity: Warning 
        Message: Remove a user from a privileged group
    EventID: 2202
        Serverity: Error
        Message: The AD Web service not avialble on a domain
    EventID:2203
        Serverity: Error
        Message: A access denied occurs while removing user from a privileged group
    EventID: 2204
        Serverity:Error
        Message: A general error occured while removing a user from a privileged group
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
    $LogLine = "$(Get-Date -Format o), [$Severity], $Message"
    Add-Content -Path $LogFile -Value $LogLine 
    #If the severity is not debug write the even to the event log and format the output
    switch ($Severity) {
        'Error' { 
            Write-Host $Message -ForegroundColor Red
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace 
            Write-EventLog -LogName "Application" -source $source -EventId $EventID -EntryType Error -Message $Message 
        }
        'Warning' { 
            Write-Host $Message -ForegroundColor Yellow 
            Write-EventLog -LogName "Application" -source $source -EventId $EventID -EntryType Warning -Message $Message
        }
        'Information' { 
            Write-Host $Message 
            Write-EventLog -LogName "Application" -source $source -EventId $EventID -EntryType Information -Message $Message
        }
    }
}

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
    try {
        $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
        #Validate the Kerboers Authentication policy exists. If not terminate the script with error code 0xA3. 
        $KerberosAuthenticationPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($KerbAuthPolName)'"
        if ($null -eq $KerberosAuthenticationPolicy){
            Write-Log -Message "Tier 0 Kerberos Authentication Policy '$KerberosPolicyName' not found on AD. Script terminates with error 0xA3" -Severity Error -EventID 2002
            return $false
        }
        $oProtectedUsersGroup = Get-ADGroup -Identity "$((Get-ADDomain -Server $Domain).DomainSID)-525" -Server $DomainDNS -Properties member
        foreach ($OU in $OrgUnits){
            if ($OU -notlike "*,DC=*"){ $OU = "$OU,$((GET-ADDomain -Server $Domain).DistinguishedName)"}
            if ($OU -like "*$DomainDN"){
                if ($null -eq (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OU'" -Server $DomainDNS)){
                    Write-Log -Message "The OU $OU doesn't exists in $DomainDNS" -Severity Warning -EventID 2100
                } else {
                    foreach ($user in (Get-ADUser -SearchBase $OU -Filter * -Properties msDS-AssignedAuthNPolicy,memberOf,UserAccountControl -SearchScope Subtree -Server $DomainDNS)){
                        if ($user.SID -like "*-500"){
                            Write-Log -Message "Built in Administrator (-500) is located in $OU" -Severity Warning -EventID 2101
                            #ignore the built-in administrator
                        } else {
                            #Kerberos Authentication Policy validation
                            if ($user.'msDS-AssignedAuthNPolicy' -ne $KerbAuthPolName){
                                Write-Log "Adding Kerberos Authentication Policy $KerbAuthPolName on $User" -Severity Information -EventID 2102
                                Set-ADUser $user -AuthenticationPolicy $KerbAuthPolName -Server $DomainDNS
                            }
                            #User account control validation
                            if (($user.UserAccountControl -BAND 1048576) -ne 1048576){
                                Set-ADAccountControl -Identity $user -AccountNotDelegated $True -Server $DomainDNS
                                Write-Log -Message "Mark $($User.DistinguishedName) as sensitive and cannot be delegated" -Severity Information -EventID 2103
                            }
                            #Protected user group validation
                            if ($AddProtectedUsersGroup -and ($oProtectedUsersGroup.member -notcontains $user.Distiguishedname)){
                                Add-ADGroupMember -Identity $oProtectedUsersGroup $user -Server $DomainDNS
                                Write-Log "User $($user.Distiguishedname) is addeded to protected users in $Domain" -Severity Information -EventID 2104
                            }
                        }
                    }
                }
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADException]{
        Write-Log "a access denied error occurs while changing $user attribute" -Severity Error -EventID 2105
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Log "Cannot enumerrate users" -Severity Error -EventID 2106
    }
    catch{
        Write-Log "A unexpected error occured $($error[0])" -Severity Error -EventID 2107
    }   
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
.EXAMPLE
    validateAndRemoveUser -SID "S-1-5-<domain sid>-<group sid>" -DomainDNS contoso.com

#>
function validateAndRemoveUser{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        #The SID uof the group
        [string] $SID,
        #The DNS domain Name
        [string] $DomainDNSName
    )
    $Group = Get-ADGroup -Identity $SID -Properties members,canonicalName -Server $DomainDNSName 
    #validate the SID exists
    if ($null -eq $Group){
        Write-Log "Can't validate $SID. This SID is not available" -Severity Warning -EventID 
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
                    ($member.objectClass       -ne "msDS-GroupManagedServiceAccount")         -and ` #ignore if the member is a GMSA
                    ($member.distinguishedName -notlike "*,$PrivilegedOUPath,*")              -and ` #ignore if the member is located in the Tier 0 user OU
                    ($member.distinguishedName -notlike "*,$PrivilegedServiceAccountOUPath*") -and ` #ignore if the member is located in the service account OU
                    ($excludeUser              -notlike "*$($member.DistinguishedName)*" )           #ignore if the member is in the exclude user list
                    ){    
                        try{
                            Write-Log -Message "remove $member from $($Group.DistinguishedName)" -Severity Warning -EventID 2201
                            Set-ADObject -Identity $Group -Remove @{member="$($member.DistinguishedName)"} -Server $DomainDNSName
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
                    }
            }
            "group"{
                $MemberDomainDN = [regex]::Match($member.DistinguishedName,"DC=.*").value
                $MemberDNSroot = (Get-ADObject -Filter "ncName -eq '$MemberDomainDN'" -SearchBase (Get-ADForest).Partitionscontainer -Properties dnsRoot).dnsRoot
                validateAndRemoveUser -SID $member.ObjectSid.Value -DomainDNSName $MemberDNSroot
            }
        }
    }        
}
#endregion


##############################################################################################################################
# Main program starts here
##############################################################################################################################
#script Version 
$ScriptVersion = "0.2.20241206"

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
Write-Log -Message "Tier Isolation computer management $Scope version $ScriptVersion started" -Severity Information -EventID 1
Write-Log -Message $MyInvocation.Line -Severity Debug -EventID 0 # writing the parameter to the log file
#region read configuration
try{
    if ($ConfigFile -eq '') {
        Write-host "AD config lesen noch implementieren $ADconfigurationPath" -ForegroundColor Red -BackgroundColor DarkGray
        #last resort if the configfile paramter is not available and no configuration is stored in the AD. check for the dafault configuration file
        if ($null -eq $config){
            if ((Test-Path -Path $DefaultConfigFile)){
                Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 0
                $config = Get-Content $DefaultConfigFile | ConvertFrom-Json            
            } else {
                Write-Log -Message "Can't find the configuration in $DefaultConfigFile or Active Directory" -Severity Error -EventID 2000
                return 0xe7
            }
        }
    }
    else {
        Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 0
        $config = Get-Content $ConfigFile | ConvertFrom-Json 
    }
}
catch {
    Write-Log -Message "error reading configuration" -Severity Error -EventID 2001
    return 0x3E8
}
#if the paramter $scope is set, it will overwrite the saved configuration
if ($null -eq $scope ){
    $scope = $config.scope
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
        Set-TierLevelIsolation -DomainDNS $Domain -OrgUnits $config.Tier0UsersPath -AddProtectedUsersGroup $T0ProtectedUsers -KerbAuthPolName $config.T0KerbAuthPolName
    } 
    if ($scope -ne "Tier-0") {
        Set-TierLevelIsolation -DomainDNS $Domain -OrgUnits $config.Tier1UsersPath -AddProtectedUsersGroup $T1ProtectedUsers -KerbAuthPolName $config.T1KerbAuthPolName
    }
    if ($config.PrivilegedGroupsCleanUp){
        foreach ($relativeSid in $PrivlegeDomainSid) {
            validateAndRemoveUser -SID "$((Get-ADDomain -server $DomainName).DomainSID)-$RelativeSid" -DomainDNSName $DomainName
        }
        #Backup Operators
        validateAndRemoveUser -SID "S-1-5-32-551" -DomainDNSName $DomainName
        #Print Operators
        validateAndRemoveUser -SID "S-1-5-32-550" -DomainDNSName $DomainName
        #Server Operators
        validateAndRemoveUser -SID "S-1-5-32-549" -DomainDNSName $DomainName
        #Server Operators
        validateAndRemoveUser -SID "S-1-5-32-548" -DomainDNSName $DomainName
        #Administrators
        validateAndRemoveUser -SID "S-1-5-32-544" -DomainDNSName $DomainName
    }
}
if ($config.PrivilegedGroupsCleanUp){
    $forestDNS = (Get-ADDomain).Forest
    $forestSID = (Get-ADDomain -Server $forestDNS).DomainSID.Value
    Write-Log "searching for unexpected users in schema admins" -Severity Debug
    validateAndRemoveUser -SID "$forestSID-518" -DomainDNSName $forestDNS
    Write-Log "searching for unexpteded users in enterprise admins" -Severity Debug
    validateAndRemoveUser -SID "$forestSID-519" -DomainDNSName $forestDNS
}
