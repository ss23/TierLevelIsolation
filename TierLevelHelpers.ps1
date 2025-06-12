<# Function create the entire OU path of the relative distinuished name without the domain component. This function
is required to provide the same OU structure in the entire forest
.SYNOPSIS 
    Create OU path in the current $DomainDNS
.DESCRIPTION
    create OU and sub OU to build the entire OU path. As an example on a DN like OU=Computers,OU=Tier 1,OU=Admin in
    contoso. The funtion create in the 1st round the OU=Admin if requried, in the 2nd round the OU=Tier 1,OU=Admin
    and so on till the entrie path is created
.PARAMETER OUPath 
    the relative OU path withou domain component
.PARAMETER DomainDNS
    Domain DNS Name
.EXAMPLE
    CreateOU -OUPath "OU=Test,OU=Demo" -DomainDNS "contoso.com"
#>
function New-TierLevelOU {
    [cmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]$OUPath,
        [Parameter(Mandatory)] [string]$DomainDNS
    )

    #load the OU path into array to create the entire path step by step
    $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
    if ($OUPath -like "*dc=*") {
        if ($OUPath -notlike "*$domainDN") {
            return $false
        }
        else {
            $OUPath = [regex]::Match($OUPath, "^(.*?)(?i)(?=,dc=)").Value
        }
    }
    #normalize OU remove 
    $OUPath = [regex]::Replace($OUPath, "\s?,\s?", ",")
    if ($OUPath.Contains("DC=")) {
        $OUPath = [regex]::Match($OUPath, "((CN|OU)=[^,]+,)+")
        $OUPath = $OUPath.Substring(0, $OUPath.Length - 1)
    }
    $aryOU = $OUPath.Split(",")
    $BuildOUPath = ""
    #walk through the entire domain 
    For ($i = $aryOU.Count; $i -ne 0; $i--) {
        #to create the Organizational unit the string OU= must be removed to the native name
        $OUName = $aryOU[$i - 1].Replace("OU=", "")
        #if this is the first run of the for loop the OU must in the root. The searbase paramenter is not required 
        if ($i -eq $aryOU.Count) {
            #create the OU if it doesn|t exists in the domain root. 
            if ([bool]!(Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchScope OneLevel -server $DomainDNS)) {
                Write-Host "$OUName doesn't exist in $OUPath. Creating OU" -ForegroundColor Green
                New-ADOrganizationalUnit -Name $OUName -Server $DomainDNS                        
            }
        }
        else {
            #create the sub ou if required
            if ([bool]!(Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase "$BuildOUPath$DomainDN" -Server $DomainDNS)) {
                Write-Host "$OUPath,$DomainDN doesn't exist. Creating" -ForegroundColor Green
                New-ADOrganizationalUnit -Name $OUName -Path "$BuildOUPath$DomainDN" -Server $DomainDNS
            }
        }
        #extend the OU searchbase with the current OU
        $BuildOUPath = "$($aryOU[$i-1]),$BuildOUPath"
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Message,
        
        [Parameter (Mandatory = $true)]
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        [string] $Severity
    )

    # TODO: Don't be lazy, put this in a better place...
    $appDataPath = "$env:LOCALAPPDATA"
    $logSubfolder = "TierLevelManagement"
    $logFileName = "TierLevelManagement.log"
    $LogFile = "$appDataPath/$logSubfolder/$logFileName"
    if (!(Test-Path -Path (Join-Path $appDataPath $logSubfolder))) {
        New-Item -ItemType Directory -Path (Join-Path $appDataPath $logSubfolder)
    }

    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format o) [$Severity] $Message"
    Add-Content -Path $LogFile -Value $LogLine

    switch ($Severity) {
        'Error' {
            Write-Host $Message -ForegroundColor Red
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace 
        }
        'Warning' { 
            Write-Host $Message -ForegroundColor Yellow 
        }
        'Information' { 
            Write-Host $Message 
        }
    }
}

class TierLevelConfiguration {
    # OUs that contain our Tier controlled objects
    [ValidateNotNullOrEmpty()][string] $OUTier0Users = "OU=Admins,OU=Tier 0,OU=Admin"
    [ValidateNotNullOrEmpty()][string] $OUTier0Computers = "OU=Computers,OU=Tier 0,OU=Admin"
    [ValidateNotNullOrEmpty()][string] $OUTier0ServiceAccounts = "OU=Service Accounts,OU=Tier 0,OU=Admin"

    [ValidateNotNullOrEmpty()][string] $Tier0ComputerGroup = "Tier 0 Computers"

    [ValidateNotNullOrEmpty()][string] $KerberosAuthenticationPolicyName = "Tier 0 Restrictions"

    # Internal version identifier
    [int] $Version = 1
}
