rule unknown_threat {

        meta:
                Author = "Rawan Amr Abdelsattar"
                Descritpion = "Detects the suspecious script SSH-One"

        strings:
                $callout_domain = "darkl0rd.com"
                $callout_url_1 = "http://darkl0rd.com:7758/SSH-T"
                $callout_url_2 = "http://darkl0rd.com:7758/SSH-One"

        condition:
                any of them

}
