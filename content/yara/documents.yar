// First-party rules (AGPL-3.0-or-later): Office macros and shortcuts. The engine extracts the
// macro source from OLE2 and OOXML documents and a shortcut's target and arguments as text
// (`target: ...` / `arguments: ...` lines), so these rules match on what they hide.

rule RMM_Macro_AutoRun_Starts_Program
{
    meta:
        id = "RMM-Y-0030"
        name = "Office macro that starts a program when the document opens"
        description = "A VBA macro with an auto-run entry point (AutoOpen, Document_Open, Workbook_Open) that runs a program or shell."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1204.002, T1059.005"
        licence = "AGPL-3.0-or-later"
    strings:
        $auto1 = /Sub\s+(Auto_?Open|AutoExec|AutoClose|Document_Open|Document_Close|Workbook_Open|Workbook_Activate)\s*\(/ nocase
        $run1 = /\bShell\s*(\(|")/ nocase
        $run2 = "WScript.Shell" nocase
        $run3 = "Shell.Application" nocase
        $run4 = "powershell" nocase
        $run5 = /CreateObject\s*\(\s*"Wscript/ nocase
        $run6 = "Win32_Process" nocase
    condition:
        $auto1 and any of ($run*)
}

rule RMM_Macro_Downloader
{
    meta:
        id = "RMM-Y-0031"
        name = "Office macro that downloads files"
        description = "A VBA macro calling URLDownloadToFile or an HTTP object."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1105, T1059.005"
        licence = "AGPL-3.0-or-later"
    strings:
        $sub = /\b(Sub|Function)\s+\w+/ nocase
        $dl1 = "URLDownloadToFile" nocase
        $dl2 = "MSXML2.XMLHTTP" nocase
        $dl3 = "WinHttp.WinHttpRequest" nocase
        $dl4 = "Microsoft.XMLHTTP" nocase
    condition:
        $sub and any of ($dl*) and filesize < 4MB
}

rule RMM_Shortcut_Hidden_Interpreter
{
    meta:
        id = "RMM-Y-0032"
        name = "Shortcut that runs a script interpreter hidden or with downloaded code"
        description = "A .lnk whose target is PowerShell, cmd, mshta or a script host, with hidden-window, encoded-command or URL arguments."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1204.002, T1547.009"
        licence = "AGPL-3.0-or-later"
    strings:
        $target = /target: [^\n]*(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32)\.exe/ nocase
        $args1 = /arguments: [^\n]*(-w(indowstyle)?\s+h(idden)?\b|-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{16,})/ nocase
        $args2 = /arguments: [^\n]*https?:\/\// nocase
        $args3 = /arguments: [^\n]*(iex|Invoke-Expression|FromBase64String)/ nocase
    condition:
        $target and any of ($args*)
}
