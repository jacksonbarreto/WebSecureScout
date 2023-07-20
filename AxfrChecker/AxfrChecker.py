import dns.resolver
import dns.dnssec
import re
from tldextract import extract


class AxfrChecker:

    @staticmethod
    def get_interface_list():
        return [
            "axfr_domain",
            "axfr_nameservers",
            "has_axfr",
        ]

    def __init__(self, website):
        self.domain = None
        self.__get_domain__(website)
        self.__nameservers = []
        self.__has_axfr = None
        self.__timeout = 5.0
        self.IP_RE = re.compile(r'^[0-9.]+$') #IPv4 only consists of 0-9 and \.
        self.axfr_nameservers = []


    def __check__(self):
        self.__get_nameservers__()
        if not self.__nameservers:
            return self

        self.__has_axfr = self.__check_axfr()

        return self

    def __get_domain__(self, domain_name_raw):
        _, td_location, tsu_location = extract(domain_name_raw)
        domain = f"{td_location}.{tsu_location}"
        self.domain = domain

    def __get_nameservers__(self):
        if self.domain is None:
            return
        try:
            nameservers = \
                [ns.to_text() for ns in self.__get_resolver__().resolve(self.domain, dns.rdatatype.NS)]
            for nameserver in nameservers:
                if self.IP_RE.fullmatch(nameserver): # It is already an IP!
                    self.__nameservers.append(nameserver)
                else:
                    # Get IP address of the nameserver
                    ns_ip = self.__get_resolver__().resolve(nameserver, dns.rdatatype.A).rrset[0].to_text()
                    self.__nameservers.append(ns_ip)
        except Exception as e:
            print(e)

    @staticmethod
    def __get_resolver__(nameserver='8.8.8.8'):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ([nameserver])
        resolver.lifetime = 15.0
        resolver.timeout = 20.0
        resolver.use_edns(0, dns.flags.CD | dns.flags.RD, 4096)
        return resolver

    def get_information(self):
        self.__check__()
        return {
            "axfr_domain": self.domain,
            "axfr_nameservers": self.axfr_nameservers,
            "nameservers": self.__nameservers,
            "has_axfr": self.__has_axfr
        }

    def __check_axfr(self):
        if self.domain is None:
            return False
        if not self.__nameservers:
            return False

        for nameserver in self.__nameservers:
            try:
                resp = dns.zone.from_xfr(dns.query.xfr(nameserver, self.domain, lifetime=self.__timeout))
                if resp:
                    self.axfr_nameservers.append(nameserver)
            except Exception as e:
                pass
                #print("error", e)

        if not self.axfr_nameservers:
            return False

        return True