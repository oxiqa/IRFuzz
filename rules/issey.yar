
/*
   YARA Rule Set
   Author: Ismail Kaleem #IRFuzz
   Date: 2020-07-12
   Identifier: PHP
   Reference: IRFuzz PHP
*/

/* Rule Set ----------------------------------------------------------------- */

rule MaliciousPHP
{
    strings:
        $system = /system\(/ fullword nocase  // localroot bruteforcers have a lot of this
        $ = "array_filter" nocase
        $ = "assert" fullword nocase
        $ = "backticks" fullword nocase
        $ = "call_user_func" nocase
        $eval = /eval\(/ fullword nocase
        $shell1 = /exec\(/ fullword nocase
        $shell2 = "shell_exec" fullword nocase
        $shell3 = "fpassthru" fullword nocase
        $shell4 = "passthru" fullword nocase
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

        $whitelist = /escapeshellcmd|escapeshellarg/ nocase

    condition:
        (not $whitelist and (any of ($shell*) and filesize < 5KB or $eval and filesize < 1KB or $system and filesize < 3KB or 5 of them or #system > 250))
}
