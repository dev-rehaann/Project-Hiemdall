rule LoJax_DXE_Marker
{
    meta:
        description = "Detects LoJax UEFI rootkit DXE driver markers"
        author      = "Persistent Threat Hunter"
        family      = "LoJax"
        severity    = "CRITICAL"
        reference   = "https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild"

    strings:
        $guid1 = { B6 63 41 D8 4B 2B F0 4A 9A 8E 7C 96 B6 C4 D2 E1 }
        $str1  = "HddS.M.S" ascii
        $str2  = "LoJax"    ascii nocase

    condition:
        any of them
}

rule CosmicStrand_Marker
{
    meta:
        description = "Detects CosmicStrand UEFI rootkit indicators"
        author      = "Persistent Threat Hunter"
        family      = "CosmicStrand"
        severity    = "CRITICAL"
        reference   = "https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/"

    strings:
        $hook1 = "__security_init_cookie" ascii
        $hook2 = "CosmicStrand"           ascii nocase
        $hook3 = { 48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 }

    condition:
        2 of them
}

rule BlackLotus_Bootkit
{
    meta:
        description = "Detects BlackLotus UEFI bootkit indicators"
        author      = "Persistent Threat Hunter"
        family      = "BlackLotus"
        severity    = "CRITICAL"
        reference   = "https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed"

    strings:
        $s1 = "BlackLotus"    ascii nocase
        $s2 = "bootmgfw.efi"  ascii nocase
        $s3 = "BootMGFW"      ascii

    condition:
        any of them
}

rule MosaicRegressor_NVRAM
{
    meta:
        description = "Detects MosaicRegressor UEFI implant NVRAM strings"
        author      = "Persistent Threat Hunter"
        family      = "MosaicRegressor"
        severity    = "CRITICAL"

    strings:
        $nvram1 = "MosaicRegressor" ascii nocase
        $nvram2 = { 4D 6F 73 61 69 63 }

    condition:
        any of them
}