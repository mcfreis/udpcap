# -*- encoding: utf-8 -*-

import select
import socket
import sys
import datetime
import struct
import time


def pcap_write_global_header(_fd):
    # d4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00 ff ff 00 00 01 00 00 00
    binStr = ''
    binStr += struct.pack('<24B', *(0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00))
    _fd.write(binStr)
    _fd.flush()


def pcap_write_entry(_fd, timestamp, dest, src, _dtg):

    udp = struct.pack("!HHHH%ds" % len(_dtg),
                      src[1],
                      dest[1],
                      8 + len(_dtg),
                      0,
                      _dtg,
                      )

    ip = struct.pack("!BBHIBBHII",
                     0x40 | 0x05,  # Version | IHL
                     0,  # DSCP | ECN
                     20 + len(udp),  # Total Length
                     0,  # Ident, Flags, Offset
                     128,  # TTL
                     17,  # Protocol (UDP)
                     0,  # Checksum
                     struct.unpack("!I", socket.inet_aton(src[0]))[0],
                     struct.unpack("!I", socket.inet_aton(dest[0]))[0],
                     )

    frame = struct.pack("!H",
                        0x0800,  # EtherType
                        )

    dtg = frame + ip + udp

    binStr = ''
    binStr += struct.pack('<L', int(time.mktime(timestamp.timetuple())))
    binStr += struct.pack('<L', timestamp.microsecond)
    binStr += struct.pack('<LL', len(dtg) + 12, len(dtg) + 12)
    binStr += struct.pack('<6B6B', *(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    binStr += struct.pack('<%ds' % len(dtg), dtg)

    _fd.write(binStr)
    _fd.flush()

try:
    proxyPort, serverHost, serverPort = sys.argv[1].split(':')
except:
    proxyPort, serverHost, serverPort = 4710, '127.0.0.1', 4711

proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    proxy.bind(('', int(proxyPort)))
except:
    sys.stderr.write('Failed to bind on port %s\n' % str(proxyPort))
    sys.exit(1)

sys.stdout.write('Ready.\n')

serveraddr = (serverHost, int(serverPort))
allsockets = [proxy]

proxysocks = dict()
origins = dict()

fd = open('file.pcap', mode='wb')
pcap_write_global_header(fd)

while True:
    try:
        rr, _rw, _re = select.select(allsockets, [], [])
    except:
        pass
    else:
        for s in rr:
            data, remoteaddr = s.recvfrom(32768)  # data, (remoteHost, remotePort)
            localaddr = s.getsockname()  # (localHost, localPort)

            # pcap_write_entry(fd, datetime.datetime.now(), localaddr, remoteaddr, data)

            # client -> ( proxy --> ) server
            if s == proxy:
                # sys.stdout.write("client %s -> proxy --> server: %s\n" % (remoteaddr, data))
                try:
                    # find proxy sock
                    p = proxysocks[remoteaddr]

                except KeyError:
                    # new client connection
                    proxysocks[remoteaddr] = p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    p.connect(serveraddr)

                    # keep local address of new socket
                    proxyaddr = p.getsockname()
                    origins[proxyaddr] = remoteaddr

                    # make it "selectable"
                    allsockets.append(p)

                p.send(data)
                # pcap_write_entry(fd, datetime.datetime.now(), serveraddr, p.getsockname(), data)
                pcap_write_entry(fd, datetime.datetime.now(), serveraddr, remoteaddr, data)

            # server -> ( proxy --> ) client
            else:
                bytes_sent = proxy.sendto(data, origins[localaddr])
                # pcap_write_entry(fd, datetime.datetime.now(), origins[localaddr], proxy.getsockname(), data)
                pcap_write_entry(fd, datetime.datetime.now(), origins[localaddr], serveraddr, data)
                # sys.stdout.write("server -> proxy --> client %s: %s\n" % (origins[localaddr], data[:bytes_sent]))
