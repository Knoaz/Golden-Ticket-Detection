# Golden-Ticket-Detection
This repository is for the PowerShell script I wrote for my graduation project.

On Windows systems, events are logged as defined by the audit policies set on objects.
Event logs are classified into several categories. These categories are application, security, setup, and system.
But the logs are not only kept in these categories because some applications log events in a custom category instead
of logging them in the default application category. In addition, recorded events are classified into five categories
to indicate their importance or content. These categories are information, warning, error, success audit and failure
audit. The logs can be accessed via the event viewer application or shell commands.

In this study, windows security logs in the domain controller were examined to detect golden tickets. Minor differences
between normal authentication events and golden ticket authentication events were noticed. These differences were used
to filter out suspicious events. The logs produced by the method used to obtain krbtgt account credentials were also
classified as suspicious events. These events have a specific event identifier to indicate what type of operation they
are referring to. Examined event types:

* Event ID 4624: An account was successfully logged on. This event is generated on the target machine when a logon session is created.
* Event ID 4662: An operation was performed on an object. This event is generated when an operation is performed on an Active Directory object.
* Event ID 4669: A Kerberos service ticket was requested. This event is generated when the Key Distribution Center receives a Kerberos
ticket request with a Ticket Granting Ticket.
* Event ID 4672: Special privileges assigned to new logon. This event is generated for new logon sessions that have been 
assigned with any sensitive privileges.

These events were used to identify three suspected cases.

1.  Domain controller synchronization: Attackers can use the _lsadump::dcsync_ command to get the krbtgt account credentials.
This command emulates a domain controller synchronization process. As a result of this process, a log is generated with 
event id 4662 that an active directory object has been accessed in the domain controller. The difference between this log
from the logs normally produced in the system is the use of administrator account credentials. The active directory object 
access logs that are normally produced in the system specify the SYSTEM as the account name. Additionally, _lsadump::dcsync_ uses
0x100 as the access mask. Access Mask is a hexadecimal value for indicating the type of access used for the operation. A value of
0x100 means that the object is accessed with extended access rights. In the PowerShell script below, the fourth line is used to 
filter events of this type.

1. Lowercase domain names: Login or ticket request logs contain a lot of information such as account name, domain name, SID, and
login ID. The domain name field may differ in operations made with a golden ticket. On these tickets, the domain name is usually
written in lowercase letters. However, on normal logons or normal ticket requests, the domain name is logged with uppercase letters
. An attacker who is aware of this difference can enter the domain name in capital letters when creating a golden ticket. However,
this detail is not known since the domain name is written in lowercase on the mimikatz GitHub page or in other examples. In the
PowerShell script below, the fifth line is used to filter events of this type.

1. Mismatch between SID and account name: Any user can be impersonated with a golden ticket. The /user parameter of the  
_kerberos::golden_ command is mandatory and any username can be entered. However, the _/id_ and _/groups_ parameters are optional
and their default values are admin or admin groups ids. Tickets that use the default value of the _/id_ parameter with an account 
name other than "Administrator" have a SID and account name mismatch. This filter detects golden tickets created by entering an 
arbitrary value on the username. In the PowerShell script below, the sixth line is used to filter events of this type.

The PowerShell script processes the security logs generated in the last fifteen minutes. The three suspicious cases mentioned 
above are filtered from these logs as "dcSyncEvents", "lowercaseDomainNameEvents" and "idMismatchEvents" respectively. The filtered
logs are combined in the variable "detectedLogs". If a suspicious event is detected, the detected events are sent as an e-mail.
This script is scheduled with the task scheduler to run every fifteen minutes on the domain controller.

This script is not signed by a trusted publisher. Therefore, the execution policy must be unrestricted or bypassed to run. 
Execution policy can be set with Set-ExecutionPolicy cmdlet.
```powershell
Set-ExecutionPolicy
   [-ExecutionPolicy] <ExecutionPolicy>
   [[-Scope] <ExecutionPolicyScope>]
   [-Force]
   [-WhatIf]
   [-Confirm]
   [<CommonParameters>]
   
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine

```


