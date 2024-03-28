import pyshark
import whois
import matplotlib.pyplot as plt

def analyse_dns_cap(filename):
    capture = pyshark.FileCapture(filename)

    domaines_resolus = {}
    serveurs_autoritatifs = {}
    entreprises_domaines = {}
    types_requete_dns = {}
    familles_adresse_ip = {}
    records_additionnels = {}
    comportements_dns_inattendus = []
    dns_responses = {}

    for pkt in capture:
        try:
            if 'DNS' in pkt:
                dns = pkt.dns
                if dns.qry_name not in domaines_resolus:
                    # Store the domain name along with the time it was resolved
                    domaines_resolus[dns.qry_name] = pkt.sniff_time
                    owner = get_domain_owner(dns.qry_name)
                    if owner:
                        entreprises_domaines[dns.qry_name] = owner

                # Extract more information from DNS packets
                if hasattr(dns, 'a'):
                    dns_responses[dns.qry_name] = dns.a
                if hasattr(dns, 'ns'):
                    serveurs_autoritatifs[dns.qry_name] = dns.ns
                if hasattr(dns, 'qry_type'):
                    types_requete_dns[dns.qry_name] = dns.qry_type
                if hasattr(dns, 'additional_records'):
                    records_additionnels[dns.qry_name] = dns.additional_records

                # Determine IP address family (IPv4 or IPv6)
            
                if 'IPV6 Layer' in str(pkt.layers):
                        print('do something with IPV6 packets')
                if 'IP Layer' in str(pkt.layers):
                        print('do something with IPV4 packets')
        except AttributeError:
            comportements_dns_inattendus.append(pkt)

    return domaines_resolus, serveurs_autoritatifs, entreprises_domaines, types_requete_dns, familles_adresse_ip, records_additionnels, comportements_dns_inattendus, dns_responses

def get_domain_owner(domaine):
    try:
        w = whois.whois(domaine)
        return w.org
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def print_results(domaines_resolus, serveurs_autoritatifs, entreprises_domaines, types_requete_dns, familles_adresse_ip, records_additionnels, comportements_dns_inattendus,dns_reponses):
   
    print("Resolved Domains: ", domaines_resolus)
    print("Authoritative Servers: ", serveurs_autoritatifs)
    print("Domain Companies: ", entreprises_domaines)
    print("DNS Query Types: ", types_requete_dns)
    print("IP Address Families: ", familles_adresse_ip)
    print("Additional Records: ", records_additionnels)
    print("Unexpected DNS Behaviors: ", comportements_dns_inattendus)
    print ("response dns", dns_reponses)

    # Create a bar chart for the types of DNS queries
    plt.bar(types_requete_dns.keys(), types_requete_dns.values())
    plt.xlabel('DNS Query Type')
    plt.ylabel('Count')
    plt.title('Count of Each Type of DNS Query')
    plt.show()


if __name__ == "__main__":
    filename = "Capturenormale.pcapng"
    results = analyse_dns_cap(filename)
    print_results(*results)