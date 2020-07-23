import sys
from ipwhois import IPWhois
import json


def main(lookupIp):
    txt = ""
    try:
        whois = IPWhois(lookupIp)
        txt += json.dumps(whois.lookup_whois(inc_nir=True), indent="\t").replace("\\n", " ; ")
    except:
        pass
    print(txt)


if __name__ == "__main__":
    main(sys.argv[1])