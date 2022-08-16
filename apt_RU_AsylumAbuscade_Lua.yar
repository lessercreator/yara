import "pe"

rule apt_Lua
{
	meta:
		hash = "*****"
	strings:
        $weirdDs = /[xt]?DDD[DGpH@x]+/
    condition:
		uint16(0) == 0x5a4d
		and
        (
            for any i in (0..pe.number_of_imports):
            (
                pe.import_details[i].library_name == "lua5.1.dll"
            )
        )
        or
        (
            pe.version_info["Comments"] == "www.lua.org" and
            pe.version_info["CompanyName"] == "Lua.org" and
            pe.version_info["FileDescription"] == "Lua Windows Standalone Interpreter" and
            pe.version_info["FileVersion"] == "5.1.5" and
            pe.version_info["OriginalFilename"] == "wlua5.1.exe" and
            pe.version_info["ProductName"] == "Lua - The Programming Language"
        )
        and
        #weirdDs >= 10
}
