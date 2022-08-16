import "pe"

rule apt_RU_AsylumAbuscade_Lua
{
	meta:
		hash = "737f08702f00e78dbe78acbeda63b73d04c1f8e741c5282a9aa1409369b6efa8"
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
