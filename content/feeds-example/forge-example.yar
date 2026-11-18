/*
   Layout example of an imported rule package (YARA Forge style). Made-up rules: they show the
   meta an importer reads (score, author, license, reference) and the pe module at work.
*/
import "pe"

rule EXAMPLE_UPX_Packed_PE
{
    meta:
        description = "Example: a PE packed with UPX"
        author = "Example Author"
        reference = "https://example.invalid/upx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        score = 40
    condition:
        uint16(0) == 0x5a4d and for any s in pe.sections : ( s.name == "UPX0" )
}

rule EXAMPLE_Feed_Marker
{
    meta:
        description = "Example: a marker string no real file carries"
        author = "Example Author"
        license = "CC0"
        score = 80
    strings:
        $a = "RMM-FEED-EXAMPLE-MARKER-7f3c"
    condition:
        $a
}
