rule SikoMode {

    meta: 
        last_updated = "2022-09-11"
        author = "Cuteness-overload"
        description = "A rule set for the detection of the SikoMode Malware"
        sha256 = "3ACA2A08CF296F1845D6171958EF0FFD1C8BDFC3E48BDD34A605CB1F7468213E"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = "houdini" ascii
        $string2 = "C:\\Users\\Public\\passwrd.txt" ascii
        $string3 = "http://cdn.altimiter.local/" ascii
        $string4 = "SikoMode" ascii
        $string5 = "nim" fullword ascii
        
    condition:
        // Not checking for filesize in case of obfuscation efforts in later iterations
        uint16(0) == 0x5A4D and 
        uint32(uint32(0x3C)) == 0x00004550 and 
        $string1 and $string2 and $string3 and $string4 and $string5
}
