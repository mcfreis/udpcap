# -*- encoding: utf-8 -*-

import random
import select
import socket
import sys
import datetime
import struct
import time
import os
import threading
from logging import getLogger

_logger = getLogger(__name__)
PCAP_FILE = 'file.pcap'


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
                     struct.unpack("!I", socket.inet_aton(socket.gethostbyname(src[0])))[0],
                     struct.unpack("!I", socket.inet_aton(socket.gethostbyname(dest[0])))[0],
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


def add_dtg(filename, timestamp, dest, src, _dtg):
    if os.path.isfile(filename):
        fd = open(filename, mode='ab')
    else:
        fd = open(filename, mode='wb')
        pcap_write_global_header(fd)
    pcap_write_entry(fd, timestamp, dest, src, _dtg)
    fd.close()


def proxy_init(proxyPort, serverHost, serverPort):

    proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        proxy.bind(('0.0.0.0', int(proxyPort)))
    except:
        _logger.debug('### Failed to bind on port %s' % str(proxyPort))
        sys.exit(1)

    _logger.debug('### Ready.')

    serveraddr = (serverHost, int(serverPort))

    return proxy, serveraddr


def proxy_run(proxy, serveraddr, runFlag, bSimUdpLoss=False):

    allsockets = [proxy]

    proxysocks = dict()
    origins = dict()

    try:
        while runFlag.isSet():
            try:
                rr, _rw, _re = select.select(allsockets, [], [], 0.01)
            except socket.timeout:
                pass
            except:
                raise
            else:
                for s in rr:
                    data, remoteaddr = s.recvfrom(32768)  # data, (remoteHost, remotePort)
                    localaddr = s.getsockname()  # (localHost, localPort)

                    # add_dtg(PCAP_FILE, datetime.datetime.now(), localaddr, remoteaddr, data)

                    # client -> ( proxy --> ) server
                    if s == proxy:
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

                        if not bSimUdpLoss or random.randint(0, 8) > 0:
                            _logger.debug("     client %s -> proxy --> server %s: %r" % (remoteaddr, serveraddr, str(data)[:20]))
                            p.send(data)
                            # add_dtg(PCAP_FILE, datetime.datetime.now(), serveraddr, p.getsockname(), data)
                            add_dtg(PCAP_FILE, datetime.datetime.now(), serveraddr, remoteaddr, data)
                        else:
                            _logger.debug("drop client %s -> proxy --> server: %r" % (remoteaddr, str(data)[:20]))

                    # server -> ( proxy --> ) client
                    else:
                        if not bSimUdpLoss or random.randint(0, 8) > 0:
                            bytes_sent = proxy.sendto(data, origins[localaddr])
                            # add_dtg(PCAP_FILE, datetime.datetime.now(), origins[localaddr], proxy.getsockname(), data)
                            add_dtg(PCAP_FILE, datetime.datetime.now(), origins[localaddr], serveraddr, data)
                            _logger.debug("     server -> proxy --> client %s: %r" % (origins[localaddr], str(data[:bytes_sent])[:20]))
                        else:
                            _logger.debug("drop server -> proxy --> client %s: %r" % (origins[localaddr], str(data)[:20]))

    except Exception as e:
        _logger.exception(e)
    _logger.debug("Exiting pcap proxy loop")


def proxy_thread(pp, sh, sp, bSimUdpLoss=False):
    s, addr = proxy_init(pp, sh, sp)
    runFlag = threading.Event()
    runFlag.set()
    pt = threading.Thread(target=proxy_run, name='PcapProxy', args=(s, addr, runFlag, bSimUdpLoss))
    pt.start()
    return s.getsockname(), runFlag


def proxy(proxyPort, serverHost, serverPort, bSimUdpLoss=False):
    proxy, serveraddr = proxy_init(proxyPort, serverHost, serverPort)
    runFlag = threading.Event()
    runFlag.set()
    proxy_run(proxy, serveraddr, runFlag, bSimUdpLoss=bSimUdpLoss)


def proxy_loop(pp, sh, sp, bSimUdpLoss=False):
    while True:
        try:
            proxy(pp, sh, sp, bSimUdpLoss=bSimUdpLoss)
        except Exception as e:
            _logger.debug('### Restarting.')


if __name__ == '__main__':
    try:
        proxyPort, serverHost, serverPort, bSimUdpLoss = sys.argv[1].split(':')
    except:
        proxyPort, serverHost, serverPort, bSimUdpLoss = 4710, '127.0.0.1', 4711, False

    proxy_loop(proxyPort, serverHost, serverPort, bSimUdpLoss=eval(bSimUdpLoss))
