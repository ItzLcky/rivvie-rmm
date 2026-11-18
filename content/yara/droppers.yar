// First-party rules (AGPL-3.0-or-later): scripts that download and run the next stage.

rule RMM_PowerShell_Download_Cradle
{
    meta:
        id = "RMM-Y-0020"
        name = "PowerShell download cradle"
        description = "PowerShell that downloads text and runs it at once (Net.WebClient DownloadString piped to Invoke-Expression)."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1059.001, T1105"
        licence = "AGPL-3.0-or-later"
    strings:
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadData" ascii wide nocase
        $dl3 = /Invoke-WebRequest[^\n]{0,200}\.Content/ nocase
        $dl4 = /\b(iwr|irm|Invoke-RestMethod)\s+[^\n]{0,200}\|\s*(iex|Invoke-Expression)/ nocase
        $run1 = /\b(iex|Invoke-Expression)\b/ nocase
        $run2 = "[Reflection.Assembly]::Load" ascii wide nocase
    condition:
        any of ($dl*) and any of ($run*) and filesize < 5MB
}

rule RMM_Shell_Download_And_Run
{
    meta:
        id = "RMM-Y-0021"
        name = "Shell script that downloads and runs code"
        description = "curl or wget piped straight into a shell, or a download made executable and run from a temporary folder."
        severity = "moderate"
        confidence = "low"
        mode = "audit"
        mitre = "T1105, T1059.004"
        licence = "AGPL-3.0-or-later"
    strings:
        $pipe = /(curl|wget)\s[^\n|;]{0,300}\|\s*(sudo\s+)?(ba|da|z)?sh\b/
        $tmp = /(curl|wget)\s[^\n]{0,300}(\/tmp|\/dev\/shm|\/var\/tmp)\/[^\n]{0,200}(\n|;|&&)[^\n]{0,100}chmod\s+(\+x|[0-7]*7[0-7]*)\s/
        // Shell scripts, or small files with no interpreter line (cron entries, one-liners).
        // Other languages' scripts quote such lines in their documentation (GNU parallel's
        // install instructions, in /usr/bin/parallel, did).
        $shell = /^#![ \t]*\S*\/(env[ \t]+)?(ba|da|z|k)?sh\b/
        $shebang = "#!"
    condition:
        ($pipe or $tmp) and ($shell at 0 or (not $shebang at 0 and filesize < 64KB)) and filesize < 1MB
}

rule RMM_Script_Dropper_VBS_JS
{
    meta:
        id = "RMM-Y-0022"
        name = "VBScript or JScript dropper"
        description = "A Windows script that downloads a file over HTTP, saves it with ADODB.Stream and runs it."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1059.005, T1059.007, T1105"
        licence = "AGPL-3.0-or-later"
    strings:
        $http1 = "MSXML2.XMLHTTP" ascii wide nocase
        $http2 = "WinHttp.WinHttpRequest" ascii wide nocase
        $http3 = "MSXML2.ServerXMLHTTP" ascii wide nocase
        $save = "ADODB.Stream" ascii wide nocase
        $savefile = "SaveToFile" ascii wide nocase
        $run1 = "WScript.Shell" ascii wide nocase
        $run2 = "Shell.Application" ascii wide nocase
    condition:
        any of ($http*) and $save and $savefile and any of ($run*)
}

rule RMM_Certutil_Download
{
    meta:
        id = "RMM-Y-0023"
        name = "certutil used to download or decode a payload"
        description = "certutil -urlcache -f http... or certutil -decode in a script: a common way to fetch tools past filters."
        severity = "moderate"
        confidence = "medium"
        mode = "audit"
        mitre = "T1105, T1140"
        licence = "AGPL-3.0-or-later"
    strings:
        $dl = /certutil(\.exe)?\s+[^\n]{0,40}-urlcache\s[^\n]{0,40}-f\s+https?:/ nocase
        $dec = /certutil(\.exe)?\s+-decode\s/ nocase
    condition:
        any of them and filesize < 2MB
}
