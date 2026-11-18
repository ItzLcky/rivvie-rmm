// First-party rules (AGPL-3.0-or-later, like the rest of the source): test files.
// Severity, confidence, mode and ATT&CK ids are in each rule's meta; see crates/rmm-scan/src/rules.rs.

rule RMM_EICAR_Test_File
{
    meta:
        id = "RMM-F-0001"
        name = "EICAR test file"
        description = "The industry's antivirus test file: harmless, used to check that detection works end to end."
        severity = "low"
        confidence = "high"
        mode = "alert"
        licence = "AGPL-3.0-or-later"
    strings:
        // The file is 68 bytes starting with this and containing the marker below; neither
        // piece alone is the test file, so this rule doesn't trip other scanners.
        $start = "X5O!P%@AP[4\\PZX54(P^)7CC)7"
        $marker = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $start at 0 and $marker and filesize < 128
}
