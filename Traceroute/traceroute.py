import socket
import time
import argparse
import json


class Traceroute:
    def __init__(self, dst_ip=None, dst_port=33434, src_ip=None, quantity=3, timeout=1, max_ttl=30, js=False):
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.quantity = quantity
        self.timeout = timeout
        self.max_ttl = max_ttl
        self.rtt = []
        self.json = js

        self.init_parser()

    def init_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("ip")
        parser.add_argument("-p", "--port", type=int, default=self.dst_port)
        parser.add_argument("-q", "--quantity", type=int, default=self.quantity)
        parser.add_argument("-w", "--waittime", type=float, default=self.timeout)
        parser.add_argument("-m", "--maxttl", type=int, default=self.max_ttl)
        parser.add_argument("-j", "--json", default=self.json, action="store_true")
        parser.add_argument("-s", "--srcip", type=str, default=self.src_ip)

        args = parser.parse_args()
        self.dst_ip = args.ip
        self.dst_port = args.port
        self.quantity = args.quantity
        self.timeout = args.waittime
        self.max_ttl = args.maxttl
        self.json = args.json
        self.src_ip = args.srcip

    def increment_dst_port(self):
        if self.dst_port == 36000:
            self.dst_port = 33434
        else:
            self.dst_port = self.dst_port + 1

    def run(self):
        for cur_ttl in range(1, self.max_ttl + 1):
            receive_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
            receive_socket.settimeout(self.timeout)
            start_time = time.time()
            send_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, cur_ttl)
            if self.src_ip is not None:
                send_socket.bind((self.src_ip, 0))
            self.rtt.append([])

            for i in range(self.quantity):
                try:
                    send_socket.sendto(b"", (self.dst_ip, self.dst_port))
                    _, addr = receive_socket.recvfrom(1024)
                    end_time = time.time()
                    self.rtt[-1].append((addr[0], round(end_time - start_time, 4)))
                except socket.error:
                    self.rtt[-1].append((-1, -1))
            receive_socket.close()
            send_socket.close()
            got_destination = False
            for addr, port in self.rtt[-1]:
                if addr == self.dst_ip and port == self.dst_port:
                    got_destination = True
                    break
            self.increment_dst_port()
            if got_destination:
                break
        self.print_answer()

    def print_answer(self):
        if self.json:
            answer = {}
            for ttl, answers in enumerate(self.rtt):
                cur_ttl = ttl + 1
                answer[cur_ttl] = []
                for addr, rtt in answers:
                    if addr == -1:
                        answer[cur_ttl].append("timeout")
                    else:
                        answer[cur_ttl].append({"address": addr, "RTT": rtt})
            print(json.dumps(answer))
        else:
            for ttl, answers in enumerate(self.rtt):
                print("ttl {}: ".format(ttl + 1), end='')
                for addr, rtt in answers:
                    if addr == -1:
                        print("timeout;", end="\t")
                    else:
                        print("address - {}, RTT - {};".format(addr, rtt), end='\t')
                print()


if __name__ == "__main__":
    tr = Traceroute()
    tr.run()
