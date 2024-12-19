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
    Version 20241219 
        Initial Version 
    

        
    The script creates a debug log in the user data app folder. This log file contains additional debug informations
    Important events are writte to the application log

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
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Error -Message $Message 
        }
        'Warning' { 
            Write-Host $Message -ForegroundColor Yellow 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Warning -Message $Message
        }
        'Information' { 
            Write-Host $Message 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Information -Message $Message
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
$ScriptVersion = "0.2.20241219"
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
$GlobalCatalog = (Get-ADDomainController -Discover -Service GlobalCatalog -NextClosestSite ).HostName
Write-Log -Message "Tier Isolation computer management $Scope version $ScriptVersion started. $($MyInvocation.Line)" -Severity Information -EventID 1000
Write-Log -Message $MyInvocation.Line -Severity Debug -EventID 1001 # writing the parameter to the log file
#region read configuration
try{
    if ($ConfigFile -eq '') {
        if ($null -ne (Get-ADObject -Filter "DistinguishedName -eq '$ADconfigurationPath'")){
            Write-Log -Message "Read config from AD configuration partition" -Severity Debug -EventID 1002
            Write-host "AD config lesen noch implementieren" -ForegroundColor Red -BackgroundColor DarkGray
            return
        } else {
            #last resort if the configfile paramter is not available and no configuration is stored in the AD. check for the dafault configuration file
            if ($null -eq $config){
                if ((Test-Path -Path $DefaultConfigFile)){
                    Write-Log -Message "Read config from $DefaultConfigFile" -Severity Debug -EventID 1100
                    $config = Get-Content $DefaultConfigFile | ConvertFrom-Json            
                } else {
                    Write-Log -Message "Can't find the configuration in $DefaultConfigFile or Active Directory" -Severity Error -EventID 1003
                    return 0xe7
                }
            }
        }
    }
    else {
        Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 1101
        $config = Get-Content $ConfigFile | ConvertFrom-Json 
    }
}
catch {
    Write-Log -Message "error reading configuration" -Severity Error -EventID 1003
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
        Write-Log "Tiering computer management: Can't find the Tier 0 computer group $($config.Tier0ComputerGroup) in the current domain. Script aborted" -Severity Error -EventID 1200
        exit 0x3EA
    } else {
        Write-Log -Message "The group $($Tier0computerGroup.DistinguishedName) has $($Tier0computerGroup.Member.Count) members" -Severity Debug -EventID 1201
    }
    if ($config.scope -ne "Tier-0"){
        $Tier1ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier1ComputerGroup)'" -Properties member
        if ($null -eq $Tier1ComputerGroup){
            Write-Log -Message "Tiering computer management: Can't find the Tier 1 computer group $($config.Tier1ComputerGroup) in the current domain" -Severity Error -EventID 1202
        }
    }
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
    Write-Log "The AD web service is not available" -Severity Error -EventID 1203
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
                    Write-Log "Missing the Tier 0 computer OU $OU" -Severity Warning  -EventID 1300
                    }
                    else {
                    #validate the computer ain the Tier 0 OU are member of the tier 0 computers group
                    $T0computers = Get-ADComputer -Filter * -SearchBase $OU -Server $Domain
                    if ($T0computers.GetType().Name -eq 'ADComputer'){
                        Write-Log -Message "Found 1 computer in $OU" -Severity Debug -EventID 1301
                    } else {
                        Write-Log -Message "Found $($T0computers.count) computers in $OU" -Severity Debug -EventID 1301
                    }
                    Foreach ($T0Computer in $T0computers) {
                        if ($Tier0ComputerGroup.member -notcontains $T0Computer.DistinguishedName ) {
                            $Tier0ComputerGroup.member += $T0Computer.DistinguishedName
                            $GroupUpdateRequired = $true
                            Write-Log "Adding $T0computer to $Tier0ComputerGroup" -Severity Information -EventID 1302
                        }
                    }
                    }
                    #Write update AD group if required
                    if ($GroupUpdateRequired) {
                        Set-ADGroup -Instance $Tier0ComputerGroup
                        Write-Log "Tier 0 computers $OU updated" -Severity Debug -EventID 1303
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
                            Write-Log "Missing Tier 1 computer OU in $DomainDN" -Severity Warning -EventID 1400
                        } else {
                            Foreach ($Computer in (Get-ADComputer -Filter * -SearchBase $OU -Server $Domain)){
                                if ($Tier1ComputerGroup.member -notcontains $computer.DistinguishedName){
                                    $Tier1ComputerGroup.member += $Computer.DistinguishedName
                                    $GroupUpdateRequired = $true
                                    Write-Log -Message "$computer added to $($config.Tier1ComputerGroup)" -Severity Information -EventID 1401
                                }
                            }
                        }
                    }
                }
            }
            catch{
                Write-Log "A unexpected error has occured while managing Tier 1 computersgroups $error" -Severity Error -EventID 1402
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
        Write-Log "The AD WebService is down or not reachable $domain $($error[0].InvocationInfo.ScriptLineNumber)" -Severity Error -EventID 1004
    }
}

$ComputerObjectToRemove = @()
$ComputerObjectToRemove = Get-UnexpectedComputerObjects -OUList $config.Tier0ComputerPath -MemberDNList $Tier0ComputerGroup.member -DomainDNSList $config.Domains
Foreach ($DelComputerDN in $ComputerObjectToRemove){ 
    Write-Log -Message "Removing computer $DelComputerDN from $($Tier0computerGroup.DistinguishedName)" -Severity Warning -EventID 1304
    $DelComputer = Get-ADComputer -Filter "DistinguishedName -eq '$DelComputerDN'" -Server "$($GlobalCatalog[0]):3268"
    Remove-ADGroupMember -Identity $Tier0ComputerGroup -Members $DelComputer -Confirm:$false
}
if ($scope -ne "Tier-0"){
    $ComputerObjectToRemove = Get-UnexpectedComputerObjects -OUList $config.Tier1ComputerPath -MemberDNList $Tier0ComputerGroup.member -DomainDNSList $config.Domains
    Foreach ($DelComputerDN in $ComputerObjectToRemove){ 
        Write-Log -Message "Removing computer $DelComputerDN from $($Tier1computerGroup.DistinguishedName)" -Severity Warning -EventID 1403
        $DelComputer = Get-ADComputer -Filter "DistinguishedName -eq '$DelComputerDN'" -Server "$($GlobalCatalog[0]):3268"
        Remove-ADGroupMember -Identity $Tier1ComputerGroup -Members $DelComputerDN -Confirm:$false
    }
}