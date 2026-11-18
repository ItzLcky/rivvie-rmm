// First-party rules (AGPL-3.0-or-later): offensive tools by the strings their builds carry.

rule RMM_Mimikatz
{
    meta:
        id = "RMM-F-0002"
        name = "Mimikatz binary"
        description = "Mimikatz, the credential dumping tool, by its module names and author tag, in a Windows program (scripts that load it are RMM-Y-0010; a document or rule file quoting the strings is not a match)."
        severity = "severe"
        confidence = "high"
        mode = "alert"
        mitre = "T1003"
        licence = "AGPL-3.0-or-later"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide nocase
        $c = "mimikatz" ascii wide nocase
        $d = "lsadump::sam" ascii wide nocase
        $e = "privilege::debug" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule RMM_CobaltStrike_Beacon
{
    meta:
        id = "RMM-F-0004"
        name = "Cobalt Strike beacon"
        description = "Strings of the Cobalt Strike beacon payload."
        severity = "severe"
        confidence = "medium"
        mode = "audit"
        mitre = "T1071.001"
        licence = "AGPL-3.0-or-later"
    strings:
        $a = "beacon.dll" ascii
        $b = "ReflectiveLoader" ascii
        $c = "%s as %s\\%s: %d" ascii
        $d = "beacon.x64.dll" ascii
    condition:
        2 of them
}

rule RMM_PowerShell_Offensive_Frameworks
{
    meta:
        id = "RMM-Y-0010"
        name = "PowerShell attack framework"
        description = "Function names of PowerSploit, Empire and Nishang: in-memory injection and credential theft from PowerShell."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1059.001"
        licence = "AGPL-3.0-or-later"
    strings:
        $a = "Invoke-Mimikatz" ascii wide nocase
        $b = "Invoke-ReflectivePEInjection" ascii wide nocase
        $c = "Invoke-Shellcode" ascii wide nocase
        $d = "Invoke-TokenManipulation" ascii wide nocase
        $e = "Get-GPPPassword" ascii wide nocase
        $f = "Invoke-Kerberoast" ascii wide nocase
        $g = "Invoke-PowerShellTcp" ascii wide nocase
    condition:
        any of them
}

rule RMM_Kerberos_Attack_Tools
{
    meta:
        id = "RMM-Y-0011"
        name = "Kerberos attack tool"
        description = "Rubeus and similar tools: ticket requests, roasting and pass-the-ticket commands."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1558"
        licence = "AGPL-3.0-or-later"
    strings:
        $a = "Rubeus" ascii wide
        $b = "asktgt" ascii wide
        $c = "kerberoast" ascii wide nocase
        $d = "asreproast" ascii wide nocase
        $e = "s4u" ascii wide
        $f = "/ptt" ascii wide
    condition:
        $a and 2 of ($b, $c, $d, $e, $f)
}
