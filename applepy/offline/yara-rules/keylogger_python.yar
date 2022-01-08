rule Keylogger_Python
{
    meta:
        description = "Rule for detecting python keylogger"
        author = "Mateusz Suchocki"

    strings:
        $a = "pynput" nocase wide ascii
        $b = "Dropbox"
        $c = "files_upload"
        $d = "Listener"
        $e = "on_press"

    condition:
        all of them
}