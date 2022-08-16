import "pe"

private rule stringz
{
    meta:
        hash = "2ca334e12006239c1f1b176942de519b55a22e564cf0f416dc6a822e90a81bd4"
    strings:
        $string4 = "%hs\\%hs\\%hs"
        $string5 = "2@2U2]2c2y2~2"
        $string7 = "??1type_info@@UAE@XZ"
        $wshopensocket = "wshtcpip.WSHOpenSocket"
    condition:
        2 of them
}

private rule pe_check
{
    meta:
        hash = "2ca334e12006239c1f1b176942de519b55a22e564cf0f416dc6a822e90a81bd4"
    condition:
        (
            pe.number_of_imports == 4 and
            pe.number_of_exports == 17 and
            pe.dll_name == "i."
        )
        or
        pe.export_details[0].offset == 18724
}

rule main
{
    meta: 
        main = "main function for calling rules"
    condition:
        uint16(0) == 0x5a4d 
        and
        stringz
}
