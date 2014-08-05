<#
.SYNOPSIS
Provides fixes to various DnsServer cmdlets, aiming to be as close as possible to a drop-in replacement.
#>

#Requires -Version 3.0
#Requires -Module CimCmdlets

Import-Module CimCmdlets -ErrorAction Stop

$Script:thisModule = [System.IO.Path]::GetFileNameWithoutExtension($PSScriptRoot)

Function Convert-DnsTimestampToDateTime {
[CmdletBinding()]
param(
    [Parameter(
        Mandatory=$true,
        ValueFromPipeline=$true
    )]
    [UInt32[]]
    $Timestamp,

    [Parameter()]
    [Switch]
    $ProcessZero
)

    Begin {
        $base = [DateTime]::SpecifyKind('1601/1/1' , 'Utc')
    }

    Process {
        foreach($ts in $Timestamp) {
            if ($ts -ne 0 -or $ProcessZero) {
                $base.AddHours($ts).ToLocalTime()
            } else {
                0
            }
        }
    }

    End {}
}

Function Get-FixedDnsServerResourceRecord {
<#
.SYNOPSIS
Uses CIM/WMI to mimick the functionality of Get-DnsServerResourceRecord.

.DESCRIPTION
Provides a drop-in replacement to Get-DnsServerResourceRecord which fixes some bugs in that cmdlet and adds some additional features.

Bugs Fixed:
- Get-DnsServerResourceRecord returns duplicate records when a sub-domain matching the zone exists
  https://connect.microsoft.com/PowerShell/feedback/details/816342/get-dnsserverresourcerecord-returns-duplicate-records-when-a-sub-domain-matching-the-zone-exists

- The Get-DnsServerResourceRecord outputs incorrect information about TXT record
  https://connect.microsoft.com/PowerShell/feedback/details/776964/

Additional Features:
- The -Name parameter accepts an array so you can return records that match multiple names.
- If the record name(s) specified in -Name end in a dot, it will be taken as a FQDN and searched exactly (instead of appending the zone).
- if the record name(s) specified in -Name consist of only an @ sign, then that is interpreted as looking for root zone records only.
- The -RRType parameter accepts an array so you can return records that match multiple RR types.
- Additional fields returned by the CIM calls are not removed, so they are accessible if needed.

.PARAMETER ComputerName
The DNS server to connect to. 

If neither a CimSession nor a ComputerName is specified, then the COMPUTERNAME environment variable will be used.

.PARAMETER CimSession
An existing CimSession to the DNS server to run the query against.

If neither a CimSession nor a ComputerName is specified, then the COMPUTERNAME environment variable will be used.

.PARAMETER ZoneName
The DNS zone to query.

.PARAMETER RRType
The DNS resource record type(s) to query. If not specified, queries all available types.

Not all record types are available on all DNS servers. This function tries to query the DNS server to determine which record types are available.

.PARAMETER Name
The record name(s) to search for.

If the name ends in a . (dot) then it is interpreted as a FQDN, and will be searched for exactly.
If the name specified is an @ sign, then it is interpreted as referring to root zone records only.
Otherwise, the name given is appended to the zone name.

.PARAMETER Node
Search only the root of the zone.

This parameter has no effect if a Name is specified, since names get appended to the root zone anyway. It only applies when searching for records of any name.

.PARAMETER Raw
Don't try to mimick Get-DnsServerResourceRecord, just return the raw objects that get returned directly from the CIM cmdlets.

No CIM properties are removed as part of the prettying process, so this is parameter is mostly for performance reasons. It should be a bit faster with Raw.

.EXAMPLE
Get-FixedDnsServerResourceRecord -ComputerName myDnsServer -ZoneName corp.company.com

Returns all possible record types of any name in the corp.company.com zone on DNS server myDnsServer.

.EXAMPLE
Get-FixedDnsServerResourceRecord -ComputerName myDnsServer -ZoneName corp.company.com -RRType A,CName -Node

Returns all A and CNAME records in the root of the corp.company.com zone.

.EXAMPLE
Get-FixedDnsServerResourceRecord -ComputerName myDnsServer -ZoneName corp.company.com -RRType MX -Name '@','prod','dev','test'

Returns MX records in the root of the zone (corp.company.com), and in the prod, dev, and test sub-domains of the zone.

#>
[CmdletBinding(DefaultParameterSetName='ComputerName')]
param(
    [Parameter(
        ParameterSetName='ComputerName'
    )]
    [String]
    $ComputerName = $env:COMPUTERNAME,

    [Parameter(
        ParameterSetName='CimSession'
    )]
    [Microsoft.Management.Infrastructure.CimSession]
    $CimSession,

    [Parameter(
        Mandatory=$true
    )]
    [ValidateScript( {
        foreach($zone in $_) {
            if ($zone -cmatch "'") {
                throw [System.ArgumentException] "ZoneName cannot contain a single quote ($zone)"
            }
        }
        $true
    } )]
    [String]
    $ZoneName,
    
    [Parameter()]
    [ValidateSet(
         'HInfo'
        ,'Afsdb'
        ,'Atma'
        ,'Isdn'
        ,'Key'
        ,'Mb'
        ,'Md'
        ,'Mf'
        ,'Mg'
        ,'MInfo'
        ,'Mr'
        ,'Mx'
        ,'NsNxt'
        ,'Rp'
        ,'Rt'
        ,'Wks'
        ,'X25'
        ,'A'
        ,'AAAA'
        ,'CName'
        ,'Ptr'
        ,'Srv'
        ,'Txt'
        ,'Wins'
        ,'WinsR'
        ,'Ns'
        ,'Soa'
        ,'NasP'
        ,'NasPtr'
        ,'DName'
        ,'Gpos'
        ,'Loc'
        ,'DhcId'
        ,'Naptr'
        ,'RRSig'
        ,'DnsKey'
        ,'DS'
        ,'NSec'
        ,'NSec3'
        ,'NSec3Param'    
    )]
    [String[]]
    [ValidateNotNullOrEmpty()]
    $RRType,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $Name,

    [Parameter()]
    [Switch]
    $Node,

    [Parameter()]
    [Switch]
    $Raw
)
    
    $dnsNS = 'root\MicrosoftDNS'
    $dnsZoneClass = 'MicrosoftDNS_Zone'

    # These are the properties we want to display by default (to make the output mimick Get-DnsServerResourceRecord)
    $defaultProps = [String[]]@('HostName','RecordType','Timestamp','TimeToLive','RecordData')
    $dispPropSet = New-Object System.Management.Automation.PSPropertySet -ArgumentList 'DefaultDisplayPropertySet',$defaultProps
    $dispPropSet = [System.Management.Automation.PSMemberInfo[]]($dispPropSet)
        
    # If a computer name is supplied instead of a CimSession, 
    # we'll create a CimSession and use it going forward.
    if($PSCmdlet.ParameterSetName -eq 'ComputerName') {
        $dnsServer = $ComputerName
        Write-Verbose "Creating CIM session to computer $dnsServer."
        $thisCim = New-CimSession -ComputerName $dnsServer -ErrorAction Stop
    } else {
        $thisCim = $CimSession
        $dnsServer = $thisCim.ComputerName
        Write-Verbose "Using supplied CIM session to computer $dnsServer."
    }

    try {
        # We'll validate the supplied zone by trying to retrieve it from the DNS server.
        $Zone = Get-CimInstance -CimSession $thisCim -Namespace $dnsNS -ClassName $dnsZoneClass -Filter "Name = '$($ZoneName)'" -ErrorAction Stop
        if (!$Zone) {
            throw "Zone '$ZoneName' not found on DNS server $dnsServer."
        }
    
        # Not all of the supported RRTypes are available on every DNS server.
        # We'll build a list of valid ones by retrieving them from the DNS server.
        $validRRTypes = @{}
        Get-CimClass -CimSession $thisCim -Namespace $dnsNS | ForEach-Object { 
            if ($_.CimClassName -imatch 'MicrosoftDNS_([a-zA-Z0-9]+)Type') {
                $thisRRType = $Matches[1]
                $validRRTypes[$thisRRType] = $_.CimClassName
            }
        }

        # Here we build a list of the RR types we'll actually be using 
        # by intersecting the requested types with the list of valid ones.
        # If none were requested, we'll use all of the valid types.
        $returnRRTypes = @{}
        if ($RRType) {
            foreach($rrt in $RRType) {
                if ($validRRTypes.Keys -inotcontains $rrt) {
                    throw [System.ArgumentException] "'$rrt' is not a valid record type on DNS server $dnsServer."
                }
                $returnRRTypes[$rrt] = $validRRTypes[$rrt]
            }
        } else {
            $returnRRTypes = $validRRTypes
        }

        # We begin enumerating all of the RR Types we're going to look for.
        foreach($rr in $returnRRTypes.GetEnumerator()) {

            # We'll build a WQL filter to get only the records from the 
            # requested zone. 
            $filter = $(

                # If Name isn't specified, then we're returning all records, 
                # even sub-domains of sub-domains. Node indicates that we only 
                # want direct children of the zone.
                if ($Node -and !$Name) {
                    "(DomainName = '$($Zone.Name)')"
                } elseif ($Name) {

                    # If one or more Names were supplied, we'll add them to the filter.
                    $(
                        $Name | ForEach-Object { 
                            if ($_ -ceq '@') {
                                $owner = $Zone.Name
                            } elseif ($_ -cmatch '\.$') {
                                $owner = $_.TrimEnd('.')
                            } else {
                                $owner = "$_.$($Zone.Name)"
                            }
                            "(OwnerName = '$owner')" 
                        }
                    ) -join ' OR '
                } else {
                    "(ContainerName = '$($Zone.Name)')"
                }
            ) -join ' AND '

            # Request the records with our filter.
            $recs = Get-CimInstance -CimSession $thisCim -Namespace $dnsNS -ClassName $rr.Value -Filter $filter 
            
            # If Raw was requested, we skip all this and give back the real output from Get-CimInstance (faster).
            # Otherwise, we add members to mimick the output of Get-DnsServerResourceRecord as much as possible.
            if ($recs -and !$Raw) {
                $recs = $recs `
                | Add-Member -MemberType ScriptProperty -Name HostName -Value { $this.OwnerName -ireplace "\.?$([RegEx]::Escape($this.ContainerName))",'' } -PassThru `
                | Add-Member -MemberType ScriptProperty -Name TimeToLive -Value { [TimeSpan]::FromSeconds($this.TTL) } -PassThru `
                | Add-Member -NotePropertyName RecordType -NotePropertyValue $rr.Name -PassThru `
                | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $dispPropSet -PassThru `
                | ForEach-Object {
                    $thisRec = $_
                    $(
                        switch ($thisRec.RecordType) {
                            'txt' {
                                # https://connect.microsoft.com/PowerShell/feedback/details/776964/
                                if ([String]::IsNullOrEmpty($thisRec.RecordData)) {
                                    $thisRec
                                } else {
                                    $thisRec | Add-Member -NotePropertyName DescriptiveText -NotePropertyValue ($thisRec.RecordData.Trim('"') -csplit '" "' -join "`r`n") -Force -PassThru
                                }
                            }
                            default {
                                $thisRec
                            }
                        }
                    ) `
                    | Add-Member -NotePropertyName RawTimestamp -NotePropertyValue $thisRec.Timestamp -PassThru `
                    | Add-Member -NotePropertyName Timestamp -NotePropertyValue ($thisRec.Timestamp | Convert-DnsTimestampToDateTime) -Force -PassThru `
                    | Add-Member -NotePropertyName RawData -NotePropertyValue $thisRec.RecordData -PassThru `
                    | Add-Member -MemberType ScriptProperty -Name RecordData -Value { $this } -Force -PassThru
                }

            }

            # A strange bug: when multiple Names are specified, even if they don't exist in the result set, 
            # every result that does exist will be duplicated and returned once for each Name specified. 
            # So if you give it 3 names, each positive result will be returned 3 times. 
            # Piping to Select-Object -Unique cleans it up.

            if ($Name -and $Name.Length -gt 1) {
                $recs | Select-Object -Unique
            } else {
                $recs
            }
        } # End RRType foreach

    } finally {

        # We want to close the CIM session we created earlier, even if a terminating error occurred.
        if ($PSCmdlet.ParameterSetName -eq 'ComputerName' -and $thisCim) {
            Write-Verbose "Removing CIM session."
            Remove-CimSession -CimSession $thisCim -ErrorAction SilentlyContinue
        }
    }
}

Function Use-DnsCmdletFixes {
<#
.SYNOPSIS
Creates aliases for the fixed functions so they effectively replace the cmdlets they fix.

.DESCRIPTION
If you want to truly use this module's functions as drop-in replacements, this function will create aliases (which are interpreted first).

This should help with existing code that calls the official cmdlets, since that code hopefully won't need to be edited after calling this.

Call it with -WhatIf to see what functions will actually get overwritten.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param()
    Get-Command -Module $Script:thisModule -Name '*-Fixed*' | ForEach-Object {
        New-Alias -Name ($_.Name -ireplace '^(.+?-)Fixed(.+?)$','$1$2') -Value $_.Name -Scope Global
    }
}

Function Undo-DnsCmdletFixes {
<#
.SYNOPSIS
Removes the aliases created by Use-DnsCmdletFixes.

.DESCRIPTION
Undoes the effect of Use-DnsCmdletFixes, effectively restoring the original cmdlets.

Call it with -WhatIf to see what aliases will be removed.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param()
    Get-Command -Module $Script:thisModule -Type Alias | ForEach-Object {
        'Alias:' | Join-Path -ChildPath $_.Name | Remove-Item -Force
    }
}

Export-ModuleMember -Function '*-Fixed*','*-DnsCmdletFixes'