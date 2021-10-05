rule Privacy_LMT_Neuster_SSL_Forced_Decryption {
    meta:
        author      = "gnh1201@gmail.com"
        description = "Forced Website SSL Decryption via Lockheed Martin/Neuster DNS"
        firstseen   = "2009-09-28"
        modified    = "2021-10-05"
        reference   = "https://github.com/gnh1201/do-not-dnsadvantage"
        reference2  = "https://crt.sh/?id=2009699957"
        cwe         = ""
        cve         = ""
        tags        = "SSL,Decryption,Reverse Proxy,DNS"

    strings:
        $domain = "search.dnsadvantage.com"
        $cert_sha356 = "23DD5258702492F01859603684881D5E2828C9623DCE1A80899F3FBEDE5C6858"
        $cert_sha1 = "8A43D6DD7F63F75B4E0B7D448C43622782D17EF8"

    condition:
        $domain or $cert_sha356 or $cert_sha1
}
