rule metasploit 
{
    strings:
        $getos = "select case getGUIType" nocase
        $getext = "select case GetOS" nocase
        $func1 = "Sub OnLoad" nocase
        $func2 = "Sub Exploit" nocase
        $func3 = "Function GetOS() as string" nocase
        $func4 = "Function GetExtName() as string" nocase

    condition:
        (all of ($get*) or 3 of ($func*))
}
