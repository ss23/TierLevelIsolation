# TierLevelIsolation
## Overview 
This is a simplified solution to implement modern tier level isolation, as described in [Protecting Tier 0 the Modern Way](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/protecting-tier-0-the-modern-way/4052851), and is based on original scripts [TierLevelIsolation by Kili69](https://github.com/Kili69/TierLevelIsolation).

The install script prepares your Active Directory domain, creating OUs groups and policies that are required to manage a modern tiered domain. It doesn't include support for multiple domains, nor forest-wide management, though you can manage each domain separately by installing multiple instances of these scripts.

Once the domain is prepared, you'll need to ensure you have enabled [Kerberos Dynamic Access Control](https://learn.microsoft.com/en-us/windows-server/identity/solution-guides/dynamic-access-control-overview#support-for-using-the-key-distribution-center-kdc-group-policy-setting-to-enable-dynamic-access-control-for-a-domain) (for both the KDC and normal Computers), then you can begin managing your computers and users into the created OUs.

The final step is to run `TierLevelManagement.ps1` as a scheduled task. This will add and remove the Kerberos policies to users and add and remove computers from the Tier 0 group. Without this, you'll have a massive amount of overhead making this approach too cumbersome in practice.

## Configuration
Ideally you perform all configuration before beginning the install, as this will make sure everything is syncronized as expected.
Configuration is stored within the SYSVOL for the domain: `\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts\TierLevelIsolation.json"`. You can copy an example configuration file from this repository and store it there and make modifications before running the install script. The install script loads the configuration from SYSVOL before starting.

If you wish to modify the configuration once already installed, you should first halt any scripts that operate over the tiered structure, make the changes in Active Directory, change the configuration file to reflect the new configuration, then begin the scripts again.

## Breakglass accounts
Once a user has a Kerberos Authentication Policy applied, the restrictions begin immediately. This means you must make sure you never apply the restriction to all Domain Users, or you may find yourself locked out.
To facilitate this, the use of a breakglass account is encourated. There are two well supported mechanisms to support this:
* The built-in Adminsitrator account will never have a Kerberos Authentication Policy applied to it by the automation in this script
* There is no restriction on an account with Tier 0 equivalent permissions being outside of the managed OU structure, allowing any account to be used as a breakglass.

## Restrictions
### Does not support an envrionment already using Kerberos Authentication Policies
Unless you're using an Authentication Silo, you cannot apply more than one policy to a user. This set of scripts will override any existing policies applied to a user, making it inappropriate for use in an environment with Authentication Policies already in-use.

### Disables NTLM authentication for Tier 0 accounts
These are Kerberos only policies. This means if someone were to attempt authentication using NTLM, it would have none of these restrictions applied. To both mitigate that issue, and protect the accounts properly, this script configures all Tier 0 accounts as [Protected Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts). This has many limitations, most notably the inability to use NTLM for authentication.

It is possible to modify the script to not include this restriction, but it also makes the tiering implementation significantly less secure, and is thus not supported.

### Users are not automatically removed from Protected Users
When an account is moved out of the Tier 0 OU we can automatically remove their Kerberos Authentication Policy, removing the restrictions on which servers they can authenticate to. However, we do not remove the user from the Protected Users group, as this could have been part of that group befroe being part of the Tiering OU.
If you want to ensure users can use NTLM again (or remove the other Protected Users restrictions), remove them from this group at the same time you remove them from the Tier 0 OU.

## Post installation tasks
### Validate Kerberos AmoringKerberos Amoring must be active to isolate Tier 0 administrators. For this purpose, the current Kerberos cache should be set with 
KLIST PURGE 
Delete and request a new Kerberos ticket (e.g. dir \\<domain>\SYSVOL). Afterwards, you have the requested Kerberos ticket with 
KLIST
Indicate. In the TGT displayed, the value "Cache Flags" should be set to 0x41 -> PRIMARY FAST
The group policy settings for Kerberos Amoring are made only in the local domain. For all other domains in the AD-Forest, the settings must be manually completed.

If Kerberos Amoring is not available validate:
#### Default Domain Policy
This enables support for Kerberos Amoring for all client computers. This is done via the setting:
Administrative Templates\System\Kerberos\Kerberos Amoring

#### Default Domain Controller Policy:
In this group policy, Kerberos Amoring is enabled at the domain level. The following settings are made for this purpose:
Administrative Template\System\KDC\Kerberos Amoring Support mode
Administrative Templates\System\Kerberos\Kerberos Amoring

### Configure your Tier 0
Managing what accounts and servers count as "tier 0" is an incredibly complicated topic and this is not something you can automate with a script (really!).
We recommend taking a staged approach where you slowly move servers and users into the relevant OUs over time, ensuring everything remains working as expected through this process. Ideally, you move all servers into the Tier 0 OU first, as servers will not stop anyone logging in (the Kerberos Authentication Policies apply to users, not servers), then add your first user and verify nothing breaks for them.
Here are some resources to help determine what should be in your Tier 0:
* https://www.semperis.com/forest-druid/
* https://specterops.github.io/TierZeroTable/