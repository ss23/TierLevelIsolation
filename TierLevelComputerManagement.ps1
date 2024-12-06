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
    Version 20241204 
        Initial Version 

        
    The script creates a debug log in the user data app folder. This log file contains additional debug informations

    Important events are writte to the application log
    EventID: 1
        Severity: Information
        Message: The script is started
    EventID: 1000
        Severity: Error
        Message: the configuration is not available the script will terminate
    EventID: 1001
        Severity: Error
        Message: The configuration file has a invalid JSON format
    EventID: 1002
        Severity: Error
        Message: The AD web service on the current domain could not be reached
    EventID: 1003 
        Severity: Error
        Message: a unexpected error has occured while updating the Tier 0 computer group
    EventID: 1004
        Severity: Error
        Message: a unexpectec error has occured while updating the Tier 1 computer group
    EventID: 1100
        Severity: Error
        Message: The Tier 0 computer group is missing or cannot be reachted
    EventID: 1101
        Severity: Warning
        Message: A Tier 0 computer is missing in a domain
    EventID: 1002
        Severity: Information
        Message: A computer object is added to the Tier 0computer group
    EventID: 1103
        Severity: Warning
        Message: A unexpected computer object is member of the Tier 0 computer group and will be removed
    EventID: 1200
        Severity: Error
        Message: The Tier 1 computer is not available
    EventID: 1201
        Severity: Warning
        Message: A Tier 1 computer of is missing in a domain
    EventID: 1202
        Severity: Information
        Message: A computer object added to the Tier 1 computer group
    EventID: 1203
        Severity: Warning
        Message: A unexpected computer object is member of the Tier 1 computer group and will be removed
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
<#
.SYNOPSIS
    detect unexpected computer object in the member list
.DESCRIPTION
    provide a list of computer distinguished names which are not localted in the correct OU or down level OU
.OUTPUTS
    A array of unexpected computers
.FUNCTIONALITY
    search for unexpected computers
.PARAMETER OUList
    A array of distunguished OU names
.PARAMETER MemberDNList
    A array Distinguished computer objects
.PARAMETER DomainDnsList
    A list of supported domain DNS names of the current forest
.EXAMPLE
    Get-UnexpectedComputerObjects -OUList @("OU=Computers,OU=Tier 0,OU=Admin","OU=Tier-1,DC=dev,DC=contoso,DC=com") ´
    -MemberDNList @("CN=MyServer,OU=Computers,OU=Tier 0,OU=Admin,DC=fabrikam,DC=com")
    this will return CN=MyServer,OU=Computers,OU=Tier 0,OU=Admin,DC=fabrikam,DC=com as result
#>

function Get-UnexpectedComputerObjects{
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $OUList,
        [Parameter (Mandatory = $true)]
        [string[]] $MemberDNList,
        [Parameter (Mandatory = $true)]
        [string[]] $DomainDnsList
    )
    $UnexpectedComputer = @() #result array 
    $FQOuList = @() #list of all possible OU path
    foreach ($DomainRoot in $DomainDnsList){
        $DomainDN = (Get-ADDomain -Server $DomainRoot).DistinguishedName
        foreach ($OU in $OUList){
            if ($OU -notlike "*DC=*"){$OU = "$OU,$DomainDN"}
            if ($OU -like "*$DomainDN") {$FQOuList += $OU}
        }
    }
    foreach ($Member in $MemberDNList ){
        $MemberOU = [regex]::Match($Member,"CN=[^,]+,(.*)").Groups[1].Value
        $found = $false
        foreach ($OU in $FQOuList){
            if ($MemberOU -like "*$OU"){
                $found = $true
                break
            }
        }
        if (!$found) { $UnexpectedComputer += $Member }
    }    
    return $UnexpectedComputer
 }
#endregion

##############################################################################################################################
# Main program starts here
##############################################################################################################################

#region constantes
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
$DefaultConfigFile = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts\Tiering.config"
$ADconfigurationPath = "CN=Tier Level Isolation,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
#endregion

#script Version 
$ScriptVersion = "0.2.20241206"
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
        if ($null -eq (Get-ADObject $ADconfigurationPath)){
            Write-Log -Message "Read config from AD configuration partition" -Severity Debug -EventID 0
            Write-host "AD config lesen noch implementieren" -ForegroundColor Red -BackgroundColor DarkGray
            return
        } else {
            #last resort if the configfile paramter is not available and no configuration is stored in the AD. check for the dafault configuration file
            if ($null -eq $config){
                if ((Test-Path -Path $DefaultConfigFile)){
                    Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 0
                    $config = Get-Content $DefaultConfigFile | ConvertFrom-Json            
                } else {
                    Write-Log -Message "Can't find the configuration in $DefaultConfigFile or Active Directory" -Severity Error -EventID 1000
                    return 0xe7
                }
            }
        }
    }
    else {
        Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 0
        $config = Get-Content $ConfigFile | ConvertFrom-Json 
    }
}
catch {
    Write-Log -Message "error reading configuration" -Severity Error -EventID 1001
    return 0x3E8
}
#if the paramter $scope is set, it will overwrite the saved configuration
if ($null -eq $scope ){
    $scope = $config.scope
}
#endregion
try {
    $Tier0ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier0ComputerGroup)'" -Properties member
    if ($null -eq $Tier0ComputerGroup) {
        Write-Log "Tiering computer management: Can't find the Tier 0 computer group $($config.Tier0ComputerGroup) in the current domain. Script aborted" -Severity Error -EventID 1100
        exit 0x3EA
    } 
    if ($config.scope -ne "Tier-0"){
        $Tier1ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier1ComputerGroup)'" -Properties member
        if ($null -eq $Tier1ComputerGroup){
            Write-Log -Message "Tiering computer management: Can't find the Tier 1 computer group $($config.Tier1ComputerGroup) in the current domain" -Severity Error -EventID 1200
        }
    }
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
    Write-Log "The AD web service is not available" -Severity Error -EventID 1002
    exit 0x3E9
}

$GroupUpdateRequired = $false
foreach ($Domain  in $config.Domains) {
    try{
        $DomainDN = (Get-ADDomain -Server $Domain).DistinguishedName  
        #region Tier0 computer group management     
        Foreach ($OU in $config.Tier0ComputerPath) {
            try{
                if ($OU -notlike "*,DC=*") { $OU = "$OU,$DomainDN" }
                if ($OU -like "*$DomainDN"){     
                    if ($null -eq (Get-ADObject -Filter "DistinguishedName -eq '$OU'" -Server $Domain)) {
                    Write-Log "Missing the Tier 0 computer OU $OU" -Severity Warning  -EventID 1101
                    }
                    else {
                    #validate the computer ain the Tier 0 OU are member of the tier 0 computers group
                    Write-Log -Message "Found $($Tier0computerGroup.Member.Count) Tier 0 computers in $domain" -Severity Debug -EventID 0
                    Foreach ($T0Computer in (Get-ADComputer -Filter * -SearchBase $OU -Server $Domain)) {
                        if ($Tier0ComputerGroup.member -notcontains $T0Computer.DistinguishedName ) {
                            $Tier0ComputerGroup.member += $T0Computer.DistinguishedName
                            $GroupUpdateRequired = $true
                            Write-Log "Adding $T0computer to $Tier0ComputerGroup" -Severity Information -EventID 1102
                        }
                    }
                    }
                    #Write update AD group if required
                    if ($GroupUpdateRequired) {
                        Set-ADGroup -Instance $Tier0ComputerGroup
                        Write-Log "Tier 0 computers $OU updated" -Severity Debug -EventID 0
                        $GroupUpdateRequired = $false
                    }
                }
            }
            catch{
                Write-Log "A unexpected error has occured $($Error) while updating $Tier0ComputerGroup" -Severity Error -EventID 1003
            }
        }
        #endregion
        #Tier 1 group management
        if ($scope -ne "Tier-0"){
            try{
                $Tier1ComputerGroup = Get-ADGroup -Identity $config.Tier1ComputerGroup -Properties member
                Foreach ($OU in $config.Tier1ComputerPath){
                    if ($OU -notlike "*,DC=*"){ $OU= "$OU,$DomainDN"}
                    if ($OU -like "*,$DomainDN"){
                        if ($null -eq (Get-ADObject -Filter "DistinguishedName -eq '$OU'" -Server $Domain)){
                            Write-Log "Missing Tier 1 computer OU in $DomainDN" -Severity Warning -EventID 1201
                        } else {
                            Foreach ($Computer in (Get-ADComputer -Filter * -SearchBase $OU -Server $Domain)){
                                if ($Tier1ComputerGroup.member -notcontains $computer.DistinguishedName){
                                    $Tier1ComputerGroup.member += $Computer.DistinguishedName
                                    $GroupUpdateRequired = $true
                                    Write-Log -Message "$computer added to $($config.Tier1ComputerGroup)" -Severity Information -EventID 1202
                                }
                            }
                        }
                    }
                }
            }
            catch{
                Write-Log "A unexpected error has occured while managing Tier 1 computersgroups $error" -Severity Error -EventID 1004
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
        Write-Log "The AD WebService is down or not reachable $domain $($error[0].InvocationInfo.ScriptLineNumber)" -Severity Error -EventID 1002
    }
}
$ComputerObjectToRemove = @()
$ComputerObjectToRemove = Get-UnexpectedComputerObjects -OUList $config.Tier0ComputerPath -MemberDNList $Tier0ComputerGroup.member -DomainDNSList $config.Domains
Foreach ($DelComputerDN in $ComputerObjectToRemove){ 
    Write-Log -Message "Removing computer $DelComputerDN from $($Tier0computerGroup.DistinguishedName)" -Severity Warning -EventID 1103
    Remove-ADGroupMember -Identity $Tier0ComputerGroup -Members $DelComputerDN -Confirm:$false
}
if ($scope -ne "Tier-0"){
    $ComputerObjectToRemove = Get-UnexpectedComputerObjects -OUList $config.Tier1ComputerPath -MemberDNList $Tier0ComputerGroup.member -DomainDNSList $config.Domains
    Foreach ($DelComputerDN in $ComputerObjectToRemove){ 
        Write-Log -Message "Removing computer $DelComputerDN from $($Tier1computerGroup.DistinguishedName)" -Severity Warning -EventID 1203
        Remove-ADGroupMember -Identity $Tier1ComputerGroup -Members $DelComputerDN -Confirm:$false
    }
}