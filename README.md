# This is a BETA VERSION please let me know if there is any error

# TierLevelIsolation
## Overview 
This solution implements Tier Level isolation as described in the blog "Protection Tier 0 the modern way". It prepares your Active Directory forest to support Kerberos Authentication Policies, creating prerequisites to isolate Tier 0 or Tier 1 and automate the Tier 0 / Tier 1 user management. The Kerberos Authentication Policy ensure privileged accounts must use Kerberos as authentication protocol and can only request Kerberos TGT on predefined computers. 
The solution automates the management of Tier 0 and Tier 1 users with Kerberos Authentication Policies through scripts. One script adds AD-Computer objects to an AD group included in the Kerberos Authentication Policy claim. Another script applies the policy to Tier 0 / Tier 1 users in the correct OU, and for Tier 0, removes users from privileged groups if they are not located in the correct OU.
The user management script ensures that users are added to the protected users group and removes users from privileged groups if they are not part of the administrator OU. 
This solution can manage Tier 0 and Tier 1 users within a single Active Directory Domain or across the entire Active Directory Forest. It utilizes scheduled tasks that run on your primary Active Directory domain, typically the Forest Root domain. 

## The scripts in a nutshell
### Install.ps1
Install the solution into you Active Directory environment
### TierLevelComputerManagement.ps1
Adds computer to the Kerberos Authentication claim group
### TierLevelUserManagement.ps1
Applies the Kerberos Authentication Policy to the Tier Level administrators

## Installation 
The installation script establishes the necessary tiering structure within one or all Active Directory domains in your forest. It prepares the Active Directory domains to support Kerberos Armoring. 
The final step of the installation involves creating a group policy on the Domain Controller OU to install scheduled tasks for management scripts. To install this solution, download the latest version from the GitHub repository. Depending on your PowerShell restrictions, sign the scripts if necessary. The installation commences with the install.ps1 script, which will guide you through the process. Ensure the Active Directory PowerShell module and the Group Policy Management PowerShell module are installed before starting the script.

Initially, the script detects if your Active Directory has multiple domains. If there is more than one domain available, it will ask if you wish to run the solution in Multi-forest mode:
    Do you want to enable the multi-domain-forest mode ([y]es / No):
If the response is [y]es, tiering will be activated across the entire forest. Subsequently, you must specify the scope of your tiering by selecting Tier 0, Tier 1, or both levels:
    Scope-Level:
    [0] Tier-0
    [1] Tier-1
    [2] Tier 0 and Tier 1
    Select which scope should be enabled (2):

Next, define the Tier 0 Admin OU by providing the relative OU path (the domain distinguished name is not required). The script will replicate the same tiering structure across all domains.

    Distinguishedname of the Tier 0 Admin OU (OU=Admins,OU=Tier 0,OU=Admin):

You have the option to define multiple tiering OUs in your environment. Additionally, specify the distinguished name of the OU where your Tier 0 service accounts are located.

It is possible to add multiple service account OUs. Define the OU where the Tier 0 member servers are located, noting that subfolders within this OU do not need separate configuration.

Provide the name of the Tier 0 Kerberos authentication policy and the name of the Active Directory group containing Tier 0 member servers. If this group does not exist, it will be created.

For Tier 1 configuration, provide the name of the group containing Tier 1 member servers; again, the group will be created if it doesn't exist. 
Specify the distinguished name of the Tier 1 administrators OU and define one or more OUs for Tier 1 member servers.

After naming the Tier 1 Kerberos Authentication Policy, decide whether to add your administrators to the protected users group. Enabling privileged group cleanup applies only to Tier 0 users, removing users from privileged groups unless they are located in the Tier 0 administrator OU or service account OU. This ensures privileged users are always correctly grouped, excluding Built-In Administrators and GMSA accounts.

In a multi-domain configuration, a group managed service account is required. The installation script will create this account. The script then copies TierLevelComputerManagement.ps1, TierLevelUserManagement.ps1, and configuration files into the SYSVOL folder (\\<domain>\SYSVOL\<domain>\scripts), and installs a group policy on the Domain Controller OU.

This group policy contains the scheduled tasks, which are initially disabled and must be enabled manually to prevent unintended administrator lockouts. Before enabling these tasks, ensure all member servers belong to the Tier 0 computers or Tier 1 computers group—both universal groups appearing once in the AD forest.



## Schedule task group policy
The TierLevel Group Policy installs the following scheduled tasks on your domain controllers within the current domain:
### Tier 0 Computer Management
This scheduled task runs every 10 minutes by default. Its purpose is to add any computer located below the Tier 0 server OU to the Tier 0 server group.
### Tier 1 Computer Management
This scheduled task runs every 10 minutes by default. Its purpose is to add any computer located below the Tier 1 server OU to the Tier 1 server group.
### Tier 0 User Management
This scheduled task applies the Kerberos Authentication Policy to any user located below the Tier 0 administrator OU.
### Tier 1 User Management
This scheduled task applies the Kerberos Authentication Policy to any user located below the Tier 1 administrator OU.
### Change User Context
If it is not possible to configure a Group Managed Service Account (GMSA) as the run account for a scheduled task via group policy, this task changes the Tier 0 and Tier 1 user management tasks from system to the GMSA.

## Tier Level Isolation scripts
### Tier Level Computer Management
This PowerShell script is designed to manage computer objects within Tier 0 and Tier 1 computer groups in an Active Directory (AD) environment. It ensures that computer objects are correctly placed in their respective Organizational Units (OUs) and updates the membership of the Tier 0 and Tier 1 computer groups accordingly.
#### Parameters
##### Configfile
This is the full quaified path to the configuration file. If this parameter is empty, the script will search for the configuration in Active Directory or on the SYSVOL path
#### scope
Defines which scope will be used. Possible scopes are:
Tier-0 only the Tier 0 computer group will be managed
Tier-1 only the Tier 1 computer group will be managed
All-Tiers   the computer group for Tier 0 and Tier1 will be managed
### Tier Level User Management
This script applies the Kerberos Authentication Policy to the users in the Tier 0 and Tier 1 user groups and adds them to the protected users group. The script allows multiple OU's for Tier 0 / 1. If configured, the script will remove unexpected users from the privileged groups and add users to the protected users group. This can be enabled or disabled in the configuration file.
#### Parameters
##### Configfile
This is the full quaified path to the configuration file. If this parameter is empty, the script will search for the configuration in Active Directory or on the SYSVOL path
### scope 
Defines which scope will be used. Possible scopes are:
Tier-0 only the Tier 0 computer group will be managed
Tier-1 only the Tier 1 computer group will be managed
All-Tiers   the computer group for Tier 0 and Tier1 will be managed
