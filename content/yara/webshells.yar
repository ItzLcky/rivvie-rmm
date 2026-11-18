// First-party rules (AGPL-3.0-or-later): web shells, the scripts attackers leave on web servers.

rule RMM_Webshell_PHP
{
    meta:
        id = "RMM-F-0003"
        name = "PHP web shell"
        description = "PHP that runs request parameters as code or shell commands."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1505.003"
        licence = "AGPL-3.0-or-later"
    strings:
        $php = "<?" ascii
        $e1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $e2 = /(system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $e3 = /(assert|eval)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $e4 = /preg_replace\s*\(\s*['"][^'"]*\/e['"]\s*,\s*\$_(GET|POST|REQUEST)/ nocase
    condition:
        $php and any of ($e*) and filesize < 2MB
}

rule RMM_Webshell_ASPX
{
    meta:
        id = "RMM-Y-0001"
        name = "ASP.NET web shell"
        description = "ASP or ASP.NET page that starts processes or evaluates code taken from the request."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1505.003"
        licence = "AGPL-3.0-or-later"
    strings:
        $page = /<%@\s*Page/ nocase
        $asp = "<%" ascii
        $req = /Request(\.Form|\.QueryString|\.Params)?\s*\[/ nocase
        $run1 = "Process.Start" nocase
        $run2 = "ProcessStartInfo" nocase
        $run3 = /eval\s*\(\s*Request/ nocase
        $run4 = /Execute\s*\(\s*Request/ nocase
        $run5 = "cmd.exe" nocase
    condition:
        ($page or $asp) and $req and 2 of ($run*) and filesize < 2MB
}

rule RMM_Webshell_JSP
{
    meta:
        id = "RMM-Y-0002"
        name = "JSP web shell"
        description = "Java Server Page that runs a request parameter as a command."
        severity = "high"
        confidence = "medium"
        mode = "audit"
        mitre = "T1505.003"
        licence = "AGPL-3.0-or-later"
    strings:
        $jsp = "<%" ascii
        $exec = /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*request\.getParameter/ nocase
        $pb = /new\s+ProcessBuilder\s*\([^)]*request\.getParameter/ nocase
    condition:
        $jsp and ($exec or $pb) and filesize < 2MB
}
