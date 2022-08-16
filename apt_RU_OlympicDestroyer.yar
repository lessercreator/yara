import "pe"

rule apt_RU_OlympicDestroyer_edb_creds
{
	meta:
		hash = "edb1ff2521fb4bf748111f92786d260d40407a2e8463dcd24bb09f908ee13eb9"
	strings:
        $chang1 = "Pyeongchang2018.com\\pcadmin"  
        $chang2 = "Pyeongchang2018.com\\PCA.GMSAdmin"  
        $chang3 = "Pyeongchang2018.com\\cert01"  
        $chang4 = "Pyeongchang2018.com\\PCA.lyncadmin"  
        $chang5 = "Pyeongchang2018.com\\PCA.lyncadmintest"  
        $chang6 = "Pyeongchang2018.com\\PCA.SMSAdmin"  
        $chang7 = "Pyeongchang2018.com\\addc.siem"  
        $chang8 = "Pyeongchang2018.com\\jinsik.park"  
        $chang9 = "Pyeongchang2018.com\\pca.infradmin"  
        $chang10 = "Pyeongchang2018.com\\PCA.KASAdmin"  
        $chang11 = "Pyeongchang2018.com\\PCA.OMEGAdmin"  
        $chang12 = "Pyeongchang2018.com\\PCA.WEBAdmin"  
        $chang13 = "Pyeongchang2018.com\\PCA.SDAdmin"  
        $chang14 = "Pyeongchang2018.com\\pca.sqladmin"  
        $chang15 = "Pyeongchang2018.com\\PCA.giwon.nam"  
        $chang16 = "Pyeongchang2018.com\\svc_all_swd_installc"  
        $chang17 = "Pyeongchang2018.com\\PCA.spsadmin"  
        $chang18 = "Pyeongchang2018.com\\test"  
        $chang19 = "Pyeongchang2018.com\\adm.pms"  
        $chang20 = "Pyeongchang2018.com\\COS.SQLAdmin"  
        $chang21 = "Pyeongchang2018.com\\pca.dnsadmin"  
        $chang22 = "Pyeongchang2018.com\\PCA.imadmin"  
        $chang23 = "Pyeongchang2018.com\\pca.perfadmin"  
        $chang24 = "Pyeongchang2018.com\\jaesang.jeong6"  
        $chang25 = "Pyeongchang2018.com\\pca.dnsadmin2"  
        $chang26 = "Pyeongchang2018.com\\pca.cpvpnadmin"  
        $chang27 = "Pyeongchang2018.com\\pca.dmzadmin"  
        $chang28 = "Pyeongchang2018.com\\PCA.ERPAdmin"  
        $chang29 = "Pyeongchang2018.com\\PCA.HRAdmin"  
        $chang30 = "Pyeongchang2018.com\\pca.ssladmin"  
        $chang31 = "Pyeongchang2018.com\\pca.mgadmin"  
        $chang32 = "Pyeongchang2018.com\\PCA.SSLVPNAdmin2"  
        $chang33 = "Pyeongchang2018.com\\pmo_admin"  
        $chang34 = "Pyeongchang2018.com\\admin"  
        $chang35 = "Pyeongchang2018.com\\web_admin"  
        $chang36 = "Pyeongchang2018.com\\cos_admin"  
        $chang37 = "Pyeongchang2018.com\\gms_admin"  
        $chang38 = "Pyeongchang2018.com\\lync.admin"  
        $chang39 = "Pyeongchang2018.com\\crm_admin"  
        $chang40 = "Pyeongchang2018.com\\ips.admin"  
        $chang41 = "Pyeongchang2018.com\\mail.admin" 

    condition:
		all of them
}

rule apt_RU_OlympicDestroyer_3e2_creds
{
	meta:
		hash = "3E27B6B287F0B9F7E85BFE18901D961110AE969D58B44AF15B1D75BE749022C2"
	strings:
        $creds1 = "ww930\\deb00999"
        $creds2 = "WW930\\w99a1mf0"
        $creds3 = "RUVOZ990FILSRV\\MICROSOFT$DPM$Acct"
        $creds4 = "WW930\\a593309"
        $creds5 = "emea\\elena.samokhvalova"
        $creds6 = "MicrosoftOffice16_Data:SSPI:elena.samokhvalova@atos.net\\(null)"
        $creds7 = "10.95.47.55\\WW930\\reportadmin"
    condition:
        all of them
}

rule apt_RU_OlympicDestroyer_ab5
{
	meta:
		hash = "ab5bf79274b6583a00be203256a4eacfa30a37bc889b5493da9456e2d5885c7f"
	strings:
        $obf = /\d\$\d,\d4\d<\dD\dL\dT\d\\\dd\dl\dt\d\|\d/
        $key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        $rant = "REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECTABLEFTHENDEFERRABLELSEXCEPTRANSACTIONATURALTERAISEXCLUSIVEXISTSAVEPOINTERSECTRIGGEREFERENCESCONSTRAINTOFFSETEMPORARYUNIQUERYWITHOUTERELEASEATTACHAVINGROUPDATEBEGINNERECURSIVEBETWEENOTNULLIKECASCADELETECASECOLLATECREATECURRENT_DATEDETACHIMMEDIATEJOINSERTMATCHPLANALYZEPRAGMABORTVALUESVIRTUALIMITWHENWHERENAMEAFTEREPLACEANDEFAULTAUTOINCREMENTCASTCOLUMNCOMMITCONFLICTCROSSCURRENT_TIMESTAMPRIMARYDEFERREDISTINCTDROPFAILFROMFULLGLOBYIFISNULLORDERESTRICTRIGHTROLLBACKROWUNIONUSINGVACUUMVIEWINITIALLY"
        $sql = "sql" nocase
    condition:
        2 of them
}

rule apt_RU_OlympicDestroyer_288_creds
{
	meta:
		hash = "28858CC6E05225F7D156D1C6A21ED11188777FA0A752CB7B56038D79A88627CC"
	strings:
        $creds1 = "ww930\\deb00999"
        $creds2 = "WW930\\w99a1mf0"
        $creds3 = "RUVOZ990FILSRV\\MICROSOFT$DPM$Acct"
        $creds4 = "WW930\\a593309"
        $creds5 = "emea\\elena.samokhvalova"
        $creds6 = "MicrosoftOffice16_Data:SSPI:elena.samokhvalova@atos.net\\$creds7 = (null)"
        $creds8 = "10.95.47.55\\WW930\\reportadmin"
        $creds9 = "WW930\\A685898"
    condition:
        all of them

}

rule apt_RU_OlympicDestroyer_misc
{
	strings:
        $eula = "%s \\\\%s -u \"%s\" -p \"%s\" -accepteula -d %s %s"
        $wmi = "Select * From Win32_ProcessStopTrace"
        $weirdDs = ">$>,>4><>D>L>T>\\>d>l>t>|>"
    condition:
        all of them
}

rule apt_RU_OlympicDestroyer_d93_creds
{
	meta:
		hash = "D934CB8D0EADB93F8A57A9B8853C5DB218D5DB78C16A35F374E413884D915016"
	strings:
        $creds1 = "ww930\\deb00999"
        $creds2 = "WW930\\w99a1mf0"
        $creds3 = "WW930\\A425253"
        $creds4 = "ATVIES2BQA\\bofh-ro"
    condition:
        all of them
}

rule apt_RU_OlympicDestroyer_wide
{
	strings:
        $cmd = "cmd.exe /c"
        $del = "del %programdata%\\evtchk.txt"
    condition:
        all of them
}