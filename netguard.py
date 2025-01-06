from scapy.all import *
import datetime
import time
import telebot
import logging

api = ""
chat_id = ""
bot = telebot.TeleBot(api)

# Настройка логирования
logging.basicConfig(filename="scan_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Списки для обнаружения
detected_ips = []
mac_table = {}
packet_counts = {}
dns_requests = {}
dos_detection = {}

def detect_scan(packet):
    global detected_ips
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        if tcp_layer.flags in ("S", ""):
            src_ip = packet[IP].src
            if src_ip not in detected_ips:
                timestamp = datetime.datetime.now()
                message = f"[*] Обнаружен подозрительный запрос от: {src_ip} в {timestamp}"
                print(message)
                bot.send_message(chat_id, message)
                logging.info(message)
                detected_ips.append((src_ip, timestamp))
                time.sleep(5)

def detect_arp_spoof(packet):
    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip in mac_table:
            if mac_table[src_ip] != src_mac:
                message = f"[!] Обнаружен ARP-спуфинг: IP {src_ip} имеет разные MAC-адреса!"
                print(message)
                bot.send_message(chat_id, message)
                logging.info(message)
        else:
            mac_table[src_ip] = src_mac

def detect_packet_flood(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip not in packet_counts:
            packet_counts[src_ip] = 0
        packet_counts[src_ip] += 1
        if packet_counts[src_ip] > 100:  # Пороговое значение
            timestamp = datetime.datetime.now()
            message = f"[!] Обнаружен флудинг: IP {src_ip} отправил более 100 пакетов за короткое время в {timestamp}"
            print(message)
            bot.send_message(chat_id, message)
            logging.info(message)
            packet_counts[src_ip] = 0

def detect_dns_requests(packet):
    if packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        if dns_layer.qr == 0:  # Это DNS-запрос
            src_ip = packet[IP].src
            queried_domain = dns_layer.qd.qname.decode()
            if src_ip not in dns_requests:
                dns_requests[src_ip] = []
            dns_requests[src_ip].append(queried_domain)
            if len(dns_requests[src_ip]) > 10:  # Пороговое значение
                timestamp = datetime.datetime.now()
                message = f"[!] Обнаружен подозрительный DNS-запрос: IP {src_ip} запрашивает {queried_domain} в {timestamp}"
                print(message)
                bot.send_message(chat_id, message)
                logging.info(message)

def detect_dos_attack(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip not in dos_detection:
            dos_detection[src_ip] = []
        dos_detection[src_ip].append(datetime.datetime.now())
        # Удаляем записи старше 1 минуты
        dos_detection[src_ip] = [t for t in dos_detection[src_ip] if (datetime.datetime.now() - t).seconds < 60]
        if len(dos_detection[src_ip]) > 600:  # Пороговое значение
            timestamp = datetime.datetime.now()
            message = f"[!] Обнаружена потенциальная DoS-атака: IP {src_ip} отправил более 200 пакетов за последнюю минуту в {timestamp}"
            print(message)
            bot.send_message(chat_id, message)
            logging.info(message)

print("Сканирование локальной сети на подозрительные запросы...")

def main():
    try:
        sniff(filter="tcp or arp or icmp or udp", prn=lambda x: (detect_scan(x), detect_arp_spoof(x), detect_packet_flood(x), detect_dns_requests(x), detect_dos_attack(x)), store=0)
    except KeyboardInterrupt:
        print("\nПрограмма остановлена.")

if __name__ == "__main__":
    from threading import Thread
    bot_thread = Thread(target=lambda: bot.polling(none_stop=True, interval=0))
    bot_thread.start()
    main()
