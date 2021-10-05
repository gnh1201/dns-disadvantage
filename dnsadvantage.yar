rule Privacy_LMT_Neuster_SSL_Forced_Decryption {
    meta:
        author      = "gnh1201@gmail.com"
        description = "Forced Website SSL Decryption via Lockheed Martin/Neuster DNS"
        firstseen   = "2009-09-28"
        modified    = "2021-10-05"
        reference   = "https://github.com/gnh1201/dnsadvantage-ssl-decryption"

    strings:
        $text_string = "search.dnsadvantage.com"
    condition:
        $text_string
}
