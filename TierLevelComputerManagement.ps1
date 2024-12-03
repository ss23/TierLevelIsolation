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
    Automated installation of Active Directory Tier Level isolation 

.DESCRIPTION
    This script installes the Kerberos Tier Level isolation
.OUTPUTS 
    None
#>

param(
    [Parameter (Mandatory = $false)]
    [string] $ConfigFile,
    [Parameter (Mandatory = $false)]
    [ValidateSet("Tier-0", "Tier-1", "All-Tiers")]
    $scope
)

#region functions
function Write-Log {
    param (
        # status message
        [Parameter(Mandatory = $true)]
        [string]
        $Message,
        #Severity of the message
        [Parameter (Mandatory = $true)]
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        $Severity,
        [Parameter (Mandatory = $true)]
        [int]$EventID
    )
    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format o), [$Severity], $Message"
    Add-Content -Path $LogFile -Value $LogLine 
    switch ($Severity) {
        'Error' { 
            Write-Host $Message -ForegroundColor Red
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace 
            Write-EventLog -LogName "Application" -source "Application" -EventId $EventID -EntryType Error -Message $Message 
        }
        'Warning' { 
            Write-Host $Message -ForegroundColor Yellow 
            Write-EventLog -LogName "Application" -source "Application" -EventId $EventID -EntryType Warning -Message $Message
        }
        'Information' { 
            Write-Host $Message 
            Write-EventLog -LogName "Application" -source "Application" -EventId $EventID -EntryType Information -Message $Message
        }
    }
}

function Get-UnexpectedComputerObjects{
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $OUList,
        [Parameter (Mandatory = $true)]
        [string[]] $MemberDNList,
        [Parameter (Mandatory = $true)]
        [string[]] $DomainDnsList
    )
    $UnexpectedComputer = @()
    $FQOuList = @()
    foreach ($DomainRoot in $DomainDnsList){
        $DomainDN = (Get-ADDomain -Server $DomainRoot).DistinguishedName
        foreach ($OU in $OUList){
            if ($OU -notlike "*DC=*"){
                $OU = "$OU,$DomainDN"
            }
            $FQOuList += $OU
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
#endregion

#script Version 
$ScriptVersion = "1.0.20241129"
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
Write-Log -Message "Tier Isolation computer management $Scope version $ScriptVersion started" -Severity Information -EventID 0
Write-Log -Message $MyInvocation.Line -Severity Debug -EventID 0
#region read configuration
try{
    if ($ConfigFile -eq '') {
        Write-Log -Message "Read config from AD configuration partition" -Severity Debug -EventID 0
        Write-host "AD config lesen noch implementieren" -ForegroundColor Red -BackgroundColor DarkGray
        Write-Host "testen of es den AD Path gibt"
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
    else {
        Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 0
        $config = Get-Content $ConfigFile | ConvertFrom-Json 
    }
}
catch {
    Write-Log -Message "error reading config file" -Severity Error -EventID 1001
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
        Write-Log "Tiering computer management: Can't find the Tier 0 computer group $($config.Tier0ComputerGroup) in the current domain. Script aborted" -Severity Error -EventID 1001
        exit 0x3EA
    } 
    if ($config.scope -ne "Tier-0"){
        $Tier1ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier1ComputerGroup)'" -Properties member
        if ($null -eq $Tier1ComputerGroup){
            Write-Log -Message "Tiering computer management: Can't find the Tier 1 computer group $($config.Tier1ComputerGroup) in the current domain" -Severity Error -EventID 1002
        }
    }
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
    Write-Log "The AD web service is not available. The group $Tier0ComputerGroupName cannot be updates" -Severity Error -EventID 1001
    exit 0x3E9
}

$GroupUpdateRequired = $false
foreach ($Domain  in $config.Domains) {
    $DomainDN = (Get-ADDomain -Server $Domain).DistinguishedName  
    #region Tier0 computer group management     
    Foreach ($OU in $config.Tier0ComputerPath) {
        if ($OU -notlike "*,DC=*") { $OU = "$OU,$DomainDN" }
        if ($OU -like "*$DomainDN"){     
            try {
                if ($null -eq (Get-ADObject -Filter "DistinguishedName -eq '$OU'" -Server $Domain)) {
                    Write-Log "Missing the Tier 0 computer OU $OU" -Severity Warning  -EventID 1003
                }
                else {
                    #validate the computer ain the Tier 0 OU are member of the tier 0 computers group
                    Write-Log -Message "Found $($Tier0computerGroup.Member.Count) Tier 0 computers in $domain" -Severity Debug -EventID 0
                    Foreach ($T0Computer in (Get-ADComputer -Filter * -SearchBase $OU -Server $Domain)) {
                        if ($Tier0ComputerGroup.member -notcontains $T0Computer.DistinguishedName ) {
                            $Tier0ComputerGroup.member += $T0Computer.DistinguishedName
                            $GroupUpdateRequired = $true
                            Write-Log "Adding $T0computer to $Tier0ComputerGroup" -Severity Information -EventID 1100
                        }
                    }
                }
                #Write update AD group if required
                if ($GroupUpdateRequired) {
                    Set-ADGroup -Instance $Tier0ComputerGroup
                    Write-Log "Tier 0 computers $OU updated" -Severity Debug -EventID 1101
                    $GroupUpdateRequired = $false
                }
            }
            catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                Write-Log "The AD WebService is down or not reachable" -Severity Error -EventID 1202
            }
            catch{
                Write-Log "A unexpected error has occured $($Error) while updating $Tier0ComputerGroup" -Severity Error -EventID 1203
            }
        }
    }
    #endregion
    #Tier Tie 1 group management
    if ($scope -ne "Tier-0"){
        try{
            $Tier1ComputerGroup = Get-ADGroup -Identity $config.Tier1ComputerGroup -Properties member
            Foreach ($OU in $config.Tier1ComputerPath){
                if ($OU -notlike "*,DC=*"){ $OU= "$OU,$DomainDN"}
                if ($OU -like "*,$DomainDN"){
                    if ($null -eq (Get-ADObject -Filter "DistinguishedName -eq '$OU'" -Server $Domain)){
                        Write-Log "Missing Tier 1 computer OU in $DomainDN" -Severity Warning -EventID 1200
                    } else {
                        Foreach ($Computer in (Get-ADComputer -Filter * -SearchBase $OU -Server $Domain)){
                            if ($Tier1ComputerGroup.member -notcontains $computer.DistinguishedName){
                                $Tier1ComputerGroup.member += $Computer.DistinguishedName
                                $GroupUpdateRequired = $true
                                Write-Log -Message "$computer added to $($config.Tier1ComputerGroup)" -Severity Information -EventID 1201
                            }
                        }
                    }
                    Write-Host "Tier 1 computer löschen"
                }
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
            Write-Log "The AD WebService is down or not reachable" -Severity Error -EventID 0
        }
        catch{
            Write-Log "A unexpected error has occured $error" -Severity Error -EventID 0
        }
    }
}
$ComputerObjectToRemove = @()
$ComputerObjectToRemove = Get-UnexpectedComputerObjects -OUList $config.Tier0ComputerPath -MemberDNList $Tier0ComputerGroup.member -DomainDNSList $config.Domains
if ($ComputerObjectToRemove.count -gt 0){
    Foreach ($DelComuterDN in $ComputerObjectToRemove){ 
        Write-Log -Message "Removing computer $DelComputerDN from $($Tier0computerGroup.DistinguishedName)" -Severity Warning -EventID 999
        $Tier0ComputerGroup.member.Remove($DelComuterDN)
    }
    Set-ADObject -Identity $Tier0ComputerGroup -Replace @{member = $Tier0ComputerGroup.member}
}
if ($scope -ne "Tier-0"){
    $ComputerObjectToRemove = Get-UnexpectedComputerObjects -OUList $config.Tier1ComputerPath -MemberDNList $Tier0ComputerGroup.member -DomainDNSList $config.Domains
    if ($ComputerObjectToRemove.count -gt 0){
        Foreach ($DelComuterDN in $ComputerObjectToRemove){ 
            Write-Log -Message "Removing computer $DelComputerDN from $($Tier1computerGroup.DistinguishedName)" -Severity Warning -EventID 999
            $Tier0ComputerGroup.member.Remove($DelComuterDN)
        }
        Set-ADObject -Identity $Tier0ComputerGroup -Replace @{member = $Tier1ComputerGroup.member}
    }
    }