import threading
from socket import *

def scan_tcp(ip, port_num):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(0.1)
    try:
        status = sock.connect_ex((ip, port_num))
        if status == 0:
            print(f"Порт {port_num}: Доступен (TCP)\n")
        else:
            print(f"Порт {port_num}: Недоступен (TCP)\n")
    finally:
        sock.close()


def scan_udp(ip, port_num):
    udp_sock = socket(AF_INET, SOCK_DGRAM)
    icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
    icmp_sock.settimeout(1.0)
    try:
        udp_sock.sendto(b'', (ip, port_num))
        udp_sock.close()
        icmp_sock.recvfrom(1024)
        print(f"Порт {port_num}: Закрыт (UDP)\n")
    except timeout:
        print(f"Порт {port_num}: Открыт (UDP)\n")
    finally:
        icmp_sock.close()


def parallel_port_check(ip, first_port, last_port, protocol_type):
    for current_port in range(first_port, last_port + 1):
        thread = threading.Thread(target=scanner, args=(ip, current_port, protocol_type))
        thread.start()


def scanner(ip, port_num, protocol_type):
    match protocol_type:
        case "TCP":
            scan_tcp(ip, port_num)
        case "UDP":
            scan_udp(ip, port_num)


def main():
    target_host = input("Укажите IP адрес для проверки: ")
    port_range = input("Укажите диапазон портов: ").split()
    selected_protocol = input("Выберите тип проверки (TCP/UDP): ").upper()

    parallel_port_check(
        target_host,
        int(port_range[0]),
        int(port_range[1]),
        selected_protocol
    )

if __name__ == "__main__":
    main()