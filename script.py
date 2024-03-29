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
    target_ip_packet_count = {ip: {'sent': 0, 'received': 0} for ip in target_ips}
    transport_protocol_count = {'UDP': 0, 'TCP': 0, 'QUIC': 0}
   
   
    for pkt in capture:
        try:
            if 'DNS' in pkt:
                dns = pkt.dns
                if dns.qry_name not in domaines_resolus:
                    domaines_resolus[dns.qry_name] = pkt.sniff_time
                    owner = get_domain_owner(dns.qry_name)
                    if owner:
                        entreprises_domaines[dns.qry_name] = owner

                if hasattr(dns, 'a'):
                    dns_responses[dns.qry_name] = dns.a
                if hasattr(dns, 'ns'):
                    serveurs_autoritatifs[dns.qry_name] = dns.ns
                if hasattr(dns, 'qry_type'):
                    types_requete_dns[dns.qry_name] = dns.qry_type
                if hasattr(dns, 'additional_records'):
                    records_additionnels[dns.qry_name] = dns.additional_records

                
            if 'IP' in pkt:
                if pkt.ip.src in target_ips:
                    target_ip_packet_count[pkt.ip.src]['sent'] += 1
                    if 'UDP' in pkt:
                        transport_protocol_count['UDP'] += 1
                    elif 'TCP' in pkt:
                        transport_protocol_count['TCP'] += 1
                    elif 'QUIC' in pkt:
                        transport_protocol_count['QUIC'] += 1
                if pkt.ip.dst in target_ips:
                    target_ip_packet_count[pkt.ip.dst]['received'] += 1
                    if 'UDP' in pkt:
                        transport_protocol_count['UDP'] += 1
                    elif 'TCP' in pkt:
                        transport_protocol_count['TCP'] += 1
                    elif 'QUIC' in pkt:
                        transport_protocol_count['QUIC'] += 1
                    
        except AttributeError:
            comportements_dns_inattendus.append(pkt)

    

    

    return domaines_resolus, serveurs_autoritatifs, entreprises_domaines, types_requete_dns, familles_adresse_ip, records_additionnels, comportements_dns_inattendus, dns_responses, target_ip_packet_count, transport_protocol_count

def get_domain_owner(domaine):
    try:
        w = whois.whois(domaine)
        return w.org
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def print_results(domaines_resolus, serveurs_autoritatifs, entreprises_domaines, types_requete_dns, familles_adresse_ip, records_additionnels, comportements_dns_inattendus, dns_responses, target_ip_packet_count, transport_protocol_count):
    print("Resolved Domains: ", domaines_resolus)
    print("Authoritative Servers: ", serveurs_autoritatifs)
    print("Domain Companies: ", entreprises_domaines)
    print("DNS Query Types: ", types_requete_dns)
    print("IP Address Families: ", familles_adresse_ip)
    print("Additional Records: ", records_additionnels)
    print("Unexpected DNS Behaviors: ", comportements_dns_inattendus)
    print("DNS Responses: ", dns_responses)
    print("Target IP Packet Count: ", target_ip_packet_count)
    print("Transport Protocol Count: ", transport_protocol_count)

if __name__ == "__main__":
    filename = "Modifsoloshadow.pcapng"
    target_ips = ["46.105.132.156","46.105.132.157"]
    results = analyse_dns_cap(filename)
    print_results(*results)