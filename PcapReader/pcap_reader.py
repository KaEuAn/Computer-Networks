
import argparse
import json
from scapy.all import *
import matplotlib.pyplot as plt
import os

data = os.path.join("Shad_Pcap", "server_drop_1.pcap")


class PcapParser:

    def __init__(self, filename=data):
        self.init_parser()
        if self.file_name is None:
            self.file_name = filename
        self.pockets = rdpcap(self.file_name)
        self.ip = None
        self.bandwidth = 25 * 512 * 1024
        self.graph_number = 1

    def init_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-f", "--file", type=str, default=None)

        args = parser.parse_args()
        self.file_name = args.file

    def get_retransmits(self):
        last_acks = {}
        retransmits = []
        for i, pocket in enumerate(self.pockets):
            # checking TCP
            if pocket.proto != 33:
                continue
            # establish new TCP connection
            if self.ip is None:
                self.ip = pocket.src
            ips = [pocket.src, pocket.dst]
            ips.sort()
            tips = tuple(ips)
            if tips not in last_acks.keys():
                last_acks[tips] = {pocket.src: {}, pocket.dst: {}}
            if (pocket.ack, pocket.seq) in last_acks[tips][pocket.src].keys():
                if last_acks[tips][pocket.src][(pocket.ack, pocket.seq)] != pocket[TCP].options[2][1]:
                    retransmits.append(i)
            else:
                last_acks[tips][pocket.src][(pocket.ack, pocket.seq)] = pocket[TCP].options[2][1]
        return retransmits

    def process_retransmits(self):
        ids = self.get_retransmits()
        with open('retransmits_id.txt', 'w') as outfile:
            json.dump(ids, outfile)
        retransmits_perc = []
        traffic = []
        time = []
        now = 1
        retransmits_now = 0
        amount_now = 0
        bytes_now = 0
        useful_now = 0
        for i, pocket in enumerate(self.pockets):
            if pocket.time > now:
                time.append(now)
                if amount_now == 0:
                    retransmits_perc.append(0)
                else:
                    retransmits_perc.append(retransmits_now/amount_now)
                retransmits_now = 0
                if bytes_now == 0:
                    traffic.append(0)
                else:
                    traffic.append(useful_now/bytes_now)
                now += 1
                amount_now = 0
                bytes_now = 0
                useful_now = 0
            if pocket.src == self.ip:
                amount_now += 1
                bytes_now += pocket.len
                if i in ids:
                    retransmits_now += 1
                else:
                    useful_now += pocket.len

        self.save_graphic(time, retransmits_perc, "time (s)", "retransmits (%)", "retransmits.png")
        self.save_graphic(time, traffic, "time (s)", "utilization %", "utilization.png")

    def save_graphic(self, x, y, xlabel, ylabel, filename):
        plt.figure(1)
        plt.plot(x, y)
        plt.ylabel(ylabel)
        plt.xlabel(xlabel)
        plt.savefig(filename)
        plt.close()
        self.graph_number += 1




if __name__ == "__main__":
    pp = PcapParser()
    pp.process_retransmits()
