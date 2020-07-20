
/*
   YARA Rule Set
   Author: Ismail Kaleem #IRFuzz
   Date: 2020-07-12
   Identifier: PHP
   Reference: IRFuzz PHP www.irfuzz.com
*/

/* Rule Set ----------------------------------------------------------------- */

rule MaliciousPHP
{
    strings:
        $system = /system\(/ fullword nocase 
        $ = "array_filter" nocase
        $ = "assert" fullword nocase
        $ = "backticks" fullword nocase
        $ = "call_user_func" nocase
        $ = "eval" fullword nocase
        $ = /exec\(/ fullword nocase
        $ = "shell_exec" fullword nocase
        $ = "fpassthru" fullword nocase
        $ = "fsockopen" fullword nocase
        $ = "function_exists" fullword nocase
        $ = "shm_open" fullword nocase
        $ = "show_source" fullword nocase
        $ = "getmygid" fullword nocase
        $ = "shmop_open" fullword nocase
        $ = "mb_ereg_replace_callback" fullword nocase
        $ = "passthru" fullword nocase
        $ = /pcntl_(exec|fork)/ fullword nocase
        $ = "posix_geteuid" fullword nocase
        $ = "posix_getgid" fullword nocase
        $ = "posix_getpgid" fullword nocase
        $ = /(fopen|fwrite|fputs|file\_put\_contents)+\s*\((.*)\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\](.*)\)/
        $ = /(exec|shell\_exec|system|passthru)+\s*\(\s*\$\_(\w+)\[(.*)\]\s*\)/
        $ = "posix_getppid" fullword nocase
        $ = "posix_getpwnam" fullword nocase
        $ = "posix_getpwuid" fullword nocase
        $ = "posix_getsid" fullword nocase
        $ = "posix_getuid" fullword nocase
        $ = "posix_kill" fullword nocase
        $ = "posix_setegid" fullword nocase
        $ = "posix_seteuid" fullword nocase
        $ = "posix_setgid" fullword nocase
        $ = "posix_setpgid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setuid" fullword nocase
        $ = "proc_open" fullword nocase
        $ = "proc_close" fullword nocase
        $ = "preg_replace" fullword nocase
        $ = "popen" fullword nocase
        $ = "register_shutdown_function" fullword nocase
        $ = "register_tick_function" fullword nocase
        $ = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)" nocase
        $ = "stream_socket_pair" nocase
        $ = "suhosin.executor.func.blacklist" nocase
        $ = "unregister_tick_function" fullword nocase
        $ = "win32_create_service" fullword nocase
        $ = "xmlrpc_decode" fullword nocase 
        $ = /ob_start\s*\(\s*[^\)]/  //ob_start('assert'); echo $_REQUEST['pass']; ob_end_flush();

        $whitelist = /escapeshellcmd|escapeshellarg|dismissed_wp_pointers/ nocase

    condition:
        (not $whitelist and (5 of them or #system > 150))
}



rule AnyMaliciousPHP
{
    strings:
        $eval1 = /eval\(/ fullword nocase
        $eval2 = /eval\(base64_decode/ fullword nocase
        $shell1 = /exec\(/ fullword nocase
        $shell2 = "shell_exec" fullword nocase
        $shell3 = "fpassthru" fullword nocase
        $shell4 = "passthru" fullword nocase
        $shell5 = "print_r($_POST['funct']($_POST['argv']));" fullword ascii
        $shell6 = "$cmd=$_POST['cmd'];" fullword ascii
        $shell7 = "op=phpinfo" fullword nocase
        $shell8 = "$cmd==" fullword nocase
        $shell9 = "@ini_get('safe_mode_exec_dir')" nocase
        $shell10 = /(exec|shell\_exec|system|passthru)+\s*\(\s*\$\_(\w+)\[(.*)\]\s*\)/
        $small1 = "array_filter" fullword nocase
        $small2 = "assert" fullword nocase
        $small3 = "pcntl_exec" fullword nocase
        $pregreplace = "preg_replace" fullword nocase
        $malshell4 = "b374k" fullword nocase
        $malshell5 = "weevely" fullword nocase
        $malshell6 = "backdoor" fullword nocase
        $malshell1 = "'ev'.'al'" fullword
        $malshell8 = "m6aa932e" fullword 
        $malshell2 = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/  //b374k
        $malshell3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/ 
        $malshell7 = "array_intersect_uassoc(array($_REQUEST[$password] => \"\"), array(1), $f);" fullword ascii
        $encode1 = /\\x[0-9a-zA-Z]{2}\\x[0-9a-zA-Z]{2}\\x[0-9a-zA-Z]{2}\\x[0-9a-zA-Z]{2}\\x[0-9a-zA-Z]{2}\\x[0-9a-zA-Z]{2}\\x[0-9a-zA-Z]{2}\\x[0-9a-zA-Z]{2}\\x[0-9a-zA-Z]{2}/
        $encode2 = /\\x00[a-z]{1}\\x00[a-z]{1}\\x00[a-z]{1}\\x00[a-z]{1}\\x00[a-z]{1}\\x00[a-z]{1}/
        $encode3 = /[!@#$.(:<-]\'\^\'/


        $system = /system\(/ fullword nocase 

        $whitelist = /escapeshellcmd|escapeshellarg/ nocase

    condition:
        (not $whitelist and (any of ($shell*) and (filesize < 4KB) or any of ($encode*) and filesize < 2KB or (any of ($small*)) and filesize < 1KB or $pregreplace and filesize < 200 or any of ($eval*) and filesize < 8KB or $system and filesize < 3KB or #system > 5 or #eval1 > 5  or #shell2 > 4 or any of ($malshell*) ))
}

rule AnyMaliciousPHPBase64
{
    strings:
        $eval1 = "eval" base64
        $shell1 = "exec" base64
        $shell2 = "shell_exec" base64
        $shell3 = "fpassthru" base64
        $shell4 = "passthru" base64
        $pregreplace = "preg_replace" base64
        $system1 = "system" base64
        $system2 = "SYSTEM" base64

        $whitelist = /escapeshellcmd|escapeshellarg/ nocase

    condition:
        (not $whitelist and (any of them or #eval1 > 5  or #shell2 > 3  ))
}


rule fopo
{
    meta:
        description = "Free Online PHP Obfuscator"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "b96a81b71d69a9bcb5a3f9f4edccb4a3c7373159d8eda874e053b23d361107f0"
        hash = "bbe5577639233b5a83c4caebf807c553430cab230f9a15ec519670dd8be6a924"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"

    strings:
        $base64_decode = /\$[a-zA-Z0-9]+=\"\\(142|x62)\\(141|x61)\\(163|x73)\\(145|x65)\\(66|x36)\\(64|x34)\\(137|x5f)\\(144|x64)\\(145|x65)\\(143|x63)\\(157|x6f)\\(144|x64)\\(145|x65)\";@eval\(/

    condition:
        all of them
}


rule hackerstrings
{

    strings:
        $ = "john.barker446" fullword nocase
        $ = "fuck" fullword nocase
        $ = "xshellnet" fullword nocase
        $ = "asshole" fullword nocase
        $ = "yahoo21.persiangig.com" nocase
        $ = "xmail.txt" nocase
        $ = "heysec.org" nocase
        $ = /x2?\.net\.ru/ nocase
        $ = "windows\\system32\\cmd.exe" nocase
        $ = "Madleets.com" nocase
        $ = "/etc/passwd" nocase
        $ = "Safe_Mode Bypass" nocase
        $ = "g00nshell" nocase
        $ = "/bin/sh" nocase
        $ = "imhabirligi.com" nocase
        $ = "zehirhacker" nocase
        $ = "cmd.exe /c" nocase
        $ = "t00ls.net" nocase
        $ = "g22b.cc" nocase
        $ = "90sec.org" nocase
        $ = "AntSword PHP Custom Spy" fullword nocase
        $ = "KingDefacer" nocase
        $ = "Antichat Shell" nocase
        $ = "brilns.com" nocase
        $ = "cmd=whoami" nocase
        $ = "SR-Crew.de.tt" nocase
        $ = "simorgh-ev.com" nocase
        $ = "blackbap.org" nocase
        $ = "mgeisler.net" nocase 
        $ = "/tmp/output.txt" nocase
        $ = "php-webshell" nocase
        $ = "popeye.snu.ac.kr" nocase
        $ = "d3vilc0de.org" nocase
        $ = "WebShell-login" nocase
        $ = "hell-z0ne.org" nocase
        $ = "/dev/null 2>" nocase
        $ = "ru.myip.ms" nocase
        $ = "FrontPage.Editor.Document" nocase
        $ = "exploit-db.com" nocase
        $ = "ak74-team.net" nocase
        $ = "priv8coder@gmail.com" nocase
        $ = "moonhack.org" nocase
        $ = "eXpl0id" nocase
        $ = "geisler.net" nocase
        $ = "w0rms.com" nocase
        $ = "private-node.net" nocase
        $ = "rohitab.com" nocase
        $ = "sectop.com" nocase
        $ = "safe_mode bypass" nocase

    condition:
        any of them
}


