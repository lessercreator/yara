import "pe"

rule pe_check
{
    meta:
        hash = "b234d6d97630983d81decec57485f9a7bb56351dd1691ac0cdf0f20a5bf792da"
    strings:
        $turla = "#%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|"
        $reg = "RegDeleteKeyExW"
    condition:
        $turla or $reg
        and
        (pe.number_of_imports == 11) 
        and
        (   
            (pe.number_of_exports == 1) 
            and 
            (
                pe.export_details[0].name == "?z@@YGXXZ" 
                or 
                pe.export_details[0].name == "DllRegisterServer"
            )
        )
}