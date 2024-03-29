import pyshark
import matplotlib.pyplot as plt
import numpy as np

def analyse_dns_cap(filenames, target_ips):
    file_ip_packet_rate = {}

    for filename in filenames:
        capture = pyshark.FileCapture(filename)
        target_ip_packet_count = {ip: {'sent': 0, 'received': 0} for ip in target_ips}
        first_packet_time = None
        last_packet_time = None

        try:
            for pkt in capture:
                try:
                    if 'IP' in pkt:
                        # Get the time of the first and last packet
                        if first_packet_time is None:
                            first_packet_time = float(pkt.sniff_time.timestamp())
                        last_packet_time = float(pkt.sniff_time.timestamp())

                        if pkt.ip.src in target_ips:
                            target_ip_packet_count[pkt.ip.src]['sent'] += 1
                        if pkt.ip.dst in target_ips:
                            target_ip_packet_count[pkt.ip.dst]['received'] += 1
                except AttributeError:
                    pass
        finally:
            capture.close()

        # Calculate the packet rate for each IP address
        duration = last_packet_time - first_packet_time
        file_ip_packet_rate[filename] = {ip: {direction: count / duration for direction, count in counts.items()} for ip, counts in target_ip_packet_count.items()}

    return file_ip_packet_rate

def plot_packet_rates(file_packet_rates, target_ips):
    fig, ax = plt.subplots(figsize=(10, 6))

    colors = ['b', 'g', 'r', 'c', 'm', 'y', 'k']
    ip_colors = {ip: colors[i % len(colors)] for i, ip in enumerate(target_ips)}

    handles = []
    labels = []

    bar_width = 0.35
    index = np.arange(len(file_packet_rates))*1.5

    for i, (filename, packet_rates) in enumerate(file_packet_rates.items()):
        for j, ip in enumerate(target_ips):
            rates = packet_rates[ip]
            color = ip_colors[ip]
            sent_bar = ax.bar(index[i] - bar_width/2 + j*bar_width, rates['sent'], bar_width, color=color)
            received_bar = ax.bar(index[i] + bar_width/2 + j*bar_width, rates['received'], bar_width, color=color, alpha=0.5)

            if filename == list(file_packet_rates.keys())[0]:
                handles.extend([sent_bar, received_bar])
                labels.extend([f'{ip} sent', f'{ip} received'])

    ax.set_xlabel('File')
    ax.set_ylabel('Packet Rate (packets/second)')
    ax.legend(handles, labels)

    plt.xticks(index, file_packet_rates.keys(), rotation=45)

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    filenames = ["Shadowhomepage.pcapng", "Uploadshadow.pcapng", "DownloadShadow.pcapng","Modifsoloshadow.pcapng","ModifDuoSameWifi.pcapng","deletefile.pcapng"]
    target_ips = ["46.105.132.156","46.105.132.157"]
    file_packet_rates = analyse_dns_cap(filenames, target_ips)
    plot_packet_rates(file_packet_rates, target_ips)