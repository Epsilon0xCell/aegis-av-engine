import "math"
import "pe"

// Example rules in the supported yara-subset grammar. Imported
// by aegis.yara_import; conversion reports name any construct
// that needed interpretation, and out-of-subset constructs
// reject the whole rule loudly.

rule Aegis_Fixture_Markers
{
    meta:
        author = "Gavin Blacklock"
        purpose = "synthetic fixture marker detection"
    strings:
        $marker = "AEGIS-SYNTHETIC" ascii wide nocase
        $ransom = "RANSOMWARE-PATTERN" fullword
        $hex = { 4D 5A ?? ?? 41 45 47 49 53 }
    condition:
        2 of them and filesize < 1MB
}

rule Aegis_PE_Header_Entropy
{
    strings:
        $mz = { 4D 5A }
    condition:
        $mz and uint16(0) == 0x5A4D and pe.number_of_sections >= 1
        and math.entropy(0, filesize) < 7.5
}
