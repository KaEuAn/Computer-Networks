import socket
import time


class Traceroute:
    def __init__(self, dst_ip, dst_port=33434, quantity=3, timeout=5, max_ttl=30):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.quantity = quantity
        self.timeout = timeout
        self.max_ttl = max_ttl
        self.rtt = []

    def run(self):
        for cur_ttl in range(1, self.max_ttl):
            receive_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
            receive_socket.settimeout(self.timeout)
            start_time = time.time()
            send_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, cur_ttl)
            self.rtt.append([])

            send_socket.sendto(b"mth", (self.dst_ip, self.dst_port))
            for i in range(self.quantity):
                try:
                    _, addr = receive_socket.recvfrom(1024)
                    end_time = time.time()
                    self.rtt[-1].append((addr, end_time - start_time))
                except socket.error:
                    self.rtt[-1].append((-1, -1))
            receive_socket.close()
            send_socket.close()
            got_destination = False
            for addr, _ in self.rtt[-1]:
                if addr == self.dst_ip:
                    got_destination = True
                    break
            if got_destination:
                break
        self.print_answer()

    def print_answer(self):
        for ttl, answers in enumerate(self.rtt):
            print("ttl {}: ".format(ttl), end='')
            for addr, rtt in answers:
                if addr == -1:
                    print("timeout;", end="")
                else:
                    print("address - {}, RTT - {};".format(addr, rtt), end='')
            print()


if __name__ == "__main__":
    tr = Traceroute("55.66.77.88")
    tr.run()