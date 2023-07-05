import dns.resolver
import dns.dnssec
from tldextract import extract


class DnssecChecker:

    @staticmethod
    def get_interface_list():
        return [
            "dnssec_domain",
            "dnssec_nameserver",
            "has_dnssec",
            "dnssec_is_valid",
            "dnssec_algorithm",
        ]

    def __init__(self, website):
        self.domain = None
        self.__get_domain__(website)
        self.nameserver = None
        self.ns_ip_address = None
        self.__dnskeys = None
        self.__dnssigs = None
        self.__algorithm_name = None
        self.__has_dnssec = False
        self.__dnssec_is_valid = False
        self.__resolver = None

    def __check__(self):
        self.__get_ns__()
        if self.__has_dnssec__():
            self.__has_dnssec = True
            self.__set_algorithm_name__()
            if self.__dnssec_is_valid__():
                self.__dnssec_is_valid = True
        return self

    def __get_domain__(self, domain_name_raw):
        _, td_location, tsu_location = extract(domain_name_raw)
        domain = f"{td_location}.{tsu_location}"
        self.domain = domain

    def __get_ns__(self):
        if self.domain is not None:
            try:
                self.nameserver = \
                    self.__get_resolver__().resolve(self.domain, dns.rdatatype.NS).rrset[0].to_text()
                self.ns_ip_address = \
                    self.__get_resolver__().resolve(self.nameserver, dns.rdatatype.A).rrset[0].to_text()
            except Exception as e:
                #print(e)
                pass

    def __set_algorithm_name__(self):
        if self.__dnskeys is not None:
            dns_key_text = str(self.__dnskeys[0])
            algorithm_code = dns_key_text.split(" ")[2]
            self.__algorithm_name = dns.dnssec.algorithm_from_text(algorithm_code).name

    @staticmethod
    def __get_resolver__(nameserver='8.8.8.8'):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ([nameserver])
        resolver.lifetime = 15.0
        resolver.timeout = 20.0
        resolver.use_edns(0, dns.flags.CD | dns.flags.DO | dns.flags.RD, 4096)
        return resolver

    def get_information(self):
        self.__check__()
        return {
            "dnssec_domain": self.domain,
            "dnssec_nameserver": self.nameserver,
            "has_dnssec": self.__has_dnssec,
            "dnssec_is_valid": self.__dnssec_is_valid,
            "dnssec_algorithm": self.__algorithm_name
        }

    def __has_dnssec__(self):
        if self.domain is not None:
            try:
                req = dns.message.make_query(self.domain, dns.rdatatype.DNSKEY, want_dnssec=True)

                self.__sec_response= dns.query.udp_with_fallback(req, self.ns_ip_address, timeout=20.0)
                self.__dnskeys, self.__dnssigs = self.__sec_response[0].answer

                if self.__dnskeys and self.__dnssigs:
                    return True
                else:
                    return False
            except Exception as e:
                #print(e)
                return False

    def __dnssec_is_valid__(self):
        try:
            q_name = dns.name.from_text(self.domain)
            dns.dnssec.validate(self.__dnskeys, self.__dnssigs,{q_name: self.__dnskeys})
            return True
        except Exception as e:
            #print(e)
            return False

if __name__ == "__main__":
    domains = ["www.kit.edu", 'www.fau.de', 'www.tu.berlin']
    #domains = ["www.ku.de","www.uni-stuttgart.de","www.filmuniversitaet.de","www.tuhh.de","www.uni-wh.de","www.tu-chemnitz.de","www.hs-coburg.de","www.hs-kempten.de","www.hm.edu","www.th-nuernberg.de","www.th-rosenheim.de","www.ksh-muenchen.de","www.tum.de"]
    for domain in domains:
        d = DnssecChecker(domain)
        print(d.get_information())
        print()
        print()