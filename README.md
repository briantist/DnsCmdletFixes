DnsCmdletFixes
==============

Provides fixes to various DnsServer cmdlets, aiming to be as close as possible to a drop-in replacement.

###### Links:
* [[blog] Get-DnsServerResourceRecord returns duplicate records when a sub-domain matching the zone exists](http://www.briantist.com/errors/get-dnsserverresourcerecord-returns-duplicate-records-when-sub-domain-matching-zone-exists/)
* [[bug report] Get-DnsServerResourceRecord returns duplicate records when a sub-domain matching the zone exists](https://connect.microsoft.com/PowerShell/feedback/details/816342/get-dnsserverresourcerecord-returns-duplicate-records-when-a-sub-domain-matching-the-zone-exists)
* [[bug report] The Get-DnsServerResourceRecord outputs incorrect information about TXT record](https://connect.microsoft.com/PowerShell/feedback/details/776964/)

## Functions

### Replacement DNS Cmdlets

#### Get-FixedDnsServerResourceRecord

##### Syntax
````
Get-FixedDnsServerResourceRecord [-ComputerName <String>] -ZoneName <String> [-RRType <String[]>] [-Name <String[]>] [-Node ] [-Raw ] [<CommonParameters>]

Get-FixedDnsServerResourceRecord [-CimSession <CimSession>] -ZoneName <String> [-RRType <String[]>] [-Name <String[]>] [-Node ] [-Raw ] [<CommonParameters>]
````

##### Description
Provides a drop-in replacement to Get-DnsServerResourceRecord which fixes some bugs in that cmdlet and adds some additional features.
    
Bugs Fixed:
- [Get-DnsServerResourceRecord returns duplicate records when a sub-domain matching the zone exists](https://connect.microsoft.com/PowerShell/feedback/details/816342/get-dnsserverresourcerecord-returns-duplicate-records-when-a-sub-domain-matching-the-zone-exists)
- [The Get-DnsServerResourceRecord outputs incorrect information about TXT record](https://connect.microsoft.com/PowerShell/feedback/details/776964/)
    
Additional Features:
- The -Name parameter accepts an array so you can return records that match multiple names.
- If the record name(s) specified in -Name end in a dot, it will be taken as a FQDN and searched exactly (instead of appending the zone).
- If the record name(s) specified in -Name consist of only an @ sign, then that is interpreted as looking for root zone records only.
- The -RRType parameter accepts an array so you can return records that match multiple RR types.
- Additional fields returned by the CIM calls are not removed, so they are accessible if needed.
- The DescriptiveText property on TXT records is returned as a mult-line string for multi-line records.

##### Examples

###### All Records
````
Get-FixedDnsServerResourceRecord -ComputerName myDnsServer -ZoneName corp.company.com
`````
Returns all possible record types of any name in the corp.company.com zone on DNS server myDnsServer.

###### Specific RR Types in root of Zone
````
Get-FixedDnsServerResourceRecord -ComputerName myDnsServer -ZoneName corp.company.com -RRType A,CName -Node
````
Returns all A and CNAME records in the root of the corp.company.com zone.

###### MX records in specific sub-domains
````
Get-FixedDnsServerResourceRecord -ComputerName myDnsServer -ZoneName corp.company.com -RRType MX -Name '@','prod','dev','test'
````
Returns MX records in the root of the zone (corp.company.com), and in the prod, dev, and test sub-domains of the zone.

##### Parameters
###### -ComputerName &lt;String&gt;
The DNS server to connect to. 

If neither a CimSession nor a ComputerName is specified, then the `COMPUTERNAME` environment variable will be used.

###### -CimSession &lt;CimSession&gt;
An existing CimSession to the DNS server to run the query against.

If neither a CimSession nor a ComputerName is specified, then the COMPUTERNAME environment variable will be used.

###### -ZoneName &lt;String&gt;
The DNS zone to query.

###### -RRType &lt;String[]&gt;
The DNS resource record type(s) to query. If not specified, queries all available types.

Not all record types are available on all DNS servers. This function tries to query the DNS server to determine which record types are available.

###### -Name &lt;String[]&gt;
The record name(s) to search for.

If the name ends in a . (dot) then it is interpreted as a FQDN, and will be searched for exactly.
If the name specified is an @ sign, then it is interpreted as referring to root zone records only.
Otherwise, the name given is appended to the zone name.

###### -Node &lt;SwitchParameter&gt;
Search only the root of the zone.

This parameter has no effect if a Name is specified, since names get appended to the root zone anyway. It only applies when searching for records of any name.

###### -Raw &lt;SwitchParameter&gt;
Don't try to mimick Get-DnsServerResourceRecord, just return the raw objects that get returned directly from the CIM cmdlets.

No CIM properties are removed as part of the prettying process, so this is parameter is mostly for performance reasons. It should be a bit faster with Raw.


### Helper Functions

#### Use-DnsCmdletFixes

##### Syntax
````
Use-DnsCmdletFixes [-WhatIf ] 
````

##### Description
If you want to truly use this module's functions as drop-in replacements, this function will create aliases (which are interpreted first).
    
This should help with existing code that calls the official cmdlets, since that code hopefully won't need to be edited after calling this.
    
Call it with -WhatIf to see what functions will actually get overwritten.

#### Undo-DnsCmdletFixes

##### Syntax
````
Undo-DnsCmdletFixes [-WhatIf ]
````

##### Description
Undoes the effect of Use-DnsCmdletFixes, effectively restoring the original cmdlets.
    
Call it with -WhatIf to see what aliases will be removed.
