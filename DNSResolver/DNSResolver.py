import socket, time
from IPython.core.debugger import set_trace

def bytes2int(a, b):
    return a * 256 + b


def int_to_bytes(a):
    return bytes([a])


def name_to_bytes(name):
    splitted = name.split(".")
    if splitted[-1] == "":
        splitted = splitted[:-1]
    print(splitted)
    ans = b""
    for part in splitted:
        ans += int_to_bytes(len(part)) + part.encode("utf-8")
    return ans + int_to_bytes(0)


def name_by_offset(raw_data, offset):
    name = ""
    while len(raw_data) > offset and raw_data[offset] != 0 and raw_data[offset] < 192:
        if len(name) > 0:
            name += "."
        count = raw_data[offset]
        for i in range(count):
            offset += 1
            name += chr(raw_data[offset])
        offset += 1
    if len(raw_data) > offset and raw_data[offset] >= 192:
        new_offset = bytes2int(raw_data[offset], raw_data[offset+1])
        new_offset -= 49152
        if len(name) > 0:
            return name + '.' + name_by_offset(raw_data, new_offset)
        return name_by_offset(raw_data, new_offset)
    return name


class IPHolder:
    def __init__(self, url, ipv4=None, ipv6=None, ttl=float("inf")):
        self.url = url
        self.IPv4 = ipv4
        self.IPv6 = ipv6
        self.ttl = time.perf_counter() + ttl

    def update(self, address, qtype, ttl):
        if qtype == 1:
            self.IPv4 = address
        if qtype == 28:
            self.IPv6 = address
        self.ttl = min(time.perf_counter() + ttl, self.ttl)

    def update_ip_value(self, qtype):
        if qtype == 1:
            self.IPv4 = socket.inet_ntop(socket.AF_INET, self.IPv4)
        if qtype == 28:
            self.IPv6 = socket.inet_ntop(socket.AF_INET6, self.IPv6)

    def is_empty(self):
        return self.IPv4 is None

    def info(self):
        answer = {}
        answer['url'] = self.url
        answer['ttl'] = self.ttl - time.perf_counter()
        answer['IPv4'] = self.IPv4
        answer['IPv6'] = self.IPv6
        return answer

    def print(self):
        print("IPHolder {}, ttl: {}, IPv4: {}, IPv6: {}".format(self.url, self.ttl, self.IPv4, self.IPv6))


def print_holders(holders):
    for k, holder in holders.items():
        holder.print()


class DNSResolver:
    def __init__(self, cache_size=10):
        self.cache = {}
        self.rootServer = IPHolder("a.root.servers.net", "198.41.0.4")
        self.cache_size = cache_size
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.id = [0, 0]
        self.query_len = 0
        self.clean_query_cache()
        self.is_tracing = False

    def clean_query_cache(self):
        self.query_cache = {"a.root.servers.net": IPHolder("a.root.servers.net", "198.41.0.4")}
        self.trace = []
        self.is_tracing = False

    def next_id(self):
        for i in (1, 0):
            self.id[i] += 1
            if self.id[i] == 256:
                self.id[i] = 0
            else:
                return

    def get_message(self, name, qtype=1):
        self.next_id()

        message = b""
        # header
        cur_id = self.id
        for byte in self.id + [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]:
            message += int_to_bytes(byte)
        message += name_to_bytes(name)
        message += int_to_bytes(0)
        message += int_to_bytes(qtype)

        # qclass
        message += int_to_bytes(0)
        message += int_to_bytes(1)
        self.query_len = len(message)
        return message, cur_id

    def parse(self, raw_data):
        answer_count = bytes2int(raw_data[6], raw_data[7])
        servers_count = bytes2int(raw_data[8], raw_data[9])
        data = raw_data[self.query_len:]
        ans = {}
        while len(data) > 0:
            offset = len(raw_data) - len(data)
            name = name_by_offset(raw_data, offset)
            qtype = bytes2int(data[2], data[3])
            ttl = bytes2int(data[8], data[9]) + bytes2int(data[6], data[7]) * 256 * 256
            dlen = bytes2int(data[10], data[11])

            if qtype == 1 or qtype == 28:
                if name not in ans.keys():
                    ans[name] = IPHolder(name)
                ans[name].update(data[12:12+dlen], qtype, ttl)
                ans[name].update_ip_value(qtype)
            if qtype == 2:
                name = name_by_offset(raw_data, len(raw_data) - len(data) + 12)
                if name not in ans.keys():
                    ans[name] = IPHolder(name)
            data = data[12+dlen:]
        return ans, answer_count > 0

    def get_udp_request(self, name, dns_server="198.41.0.4", dns_port=53, qtype=1):
        message, cur_id = self.get_message(name, qtype)
        is_loaded = False
        for i in range(5):
            try:
                self.socket.sendto(message, (dns_server, dns_port))
                raw_data, addr = self.socket.recvfrom(1000)
                #print(raw_data)
                if raw_data[0] != cur_id[0] or raw_data[1] != cur_id[1]:
                    raise Exception("retry")
                is_loaded = True
            except:
                continue
            break
        if not is_loaded:
            raise Exception("timeout search of {}, dns_server {}, dns_port{}".format(name, dns_server, dns_port))
        return raw_data

    def lookup(self, domain, start_server=None, is_query=True):
        if not is_query and domain in self.query_cache:
            return
        if start_server is None:
            start_server = self.rootServer.url
            if is_query:
                self.cache[domain] = {"TTL": float("inf"), "holders": []}
        server, name = start_server, domain
        #print("server", server, self.query_cache[server].IPv4, "name", name)
        holders, is_answer = self.parse(self.get_udp_request(name, self.query_cache[server].IPv4, 53))
        #print_holders(holders)
        #print(is_answer)

        if not is_answer:
            if self.is_tracing:
                self.trace.append(server)
            for url, holder in holders.items():
                if not holder.is_empty():
                    if url in self.query_cache.keys():
                        if self.query_cache[url].is_empty():
                            self.query_cache[url] = holder
                    else:
                        self.query_cache[url] = holder
                    self.lookup(name, url, is_query)
                else:
                    if url not in self.query_cache.keys() or self.query_cache[url].is_empty():
                        self.lookup(url, start_server=server, is_query=False)
                    if url not in self.query_cache.keys() or self.query_cache[url].is_empty():
                        self.lookup(url, start_server=None, is_query=False)
                    self.lookup(name, url, is_query)
        elif is_query:
            if self.is_tracing:
                self.trace.append(server)
            holders6, is_answer6 = self.parse(self.get_udp_request(domain, self.query_cache[server].IPv4, 53, qtype=28))
            for url, holder in holders.items():
                if url in holders6.keys():
                    holder6 = holders6[url]
                    holder.update(holder6.IPv6, 28, holder6.ttl)
                self.cache[domain]["holders"].append(holder)
        else:
            if self.is_tracing:
                self.trace.append(server)
            for url, holder in holders.items():
                if holder.is_empty():
                    continue
                self.query_cache[url] = holder


    def get_ip(self, domain, trace=False):
        self.clean_query_cache()
        if trace:
            self.is_tracing = True
        if trace or domain not in self.cache.keys() or self.cache[domain]["TTL"] < time.perf_counter():
            self.lookup(domain)
            for holder in self.cache[domain]["holders"]:
                if self.cache[domain]["TTL"] > holder.ttl:
                    self.cache[domain]["TTl"] = holder.ttl

            answer = {"IPv4": set(), "IPv6": set()}
            for holder in self.cache[domain]["holders"]:
                if holder.IPv4 is not None:
                    answer["IPv4"].add(holder.IPv4)
                if holder.IPv6 is not None:
                    answer["IPv6"].add(holder.IPv6)
            self.cache[domain]["holders"] = answer
        return self.cache[domain]["holders"], self.trace


if __name__ == "__main__":
    pass
