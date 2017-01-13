# -*- encoding: utf-8 -*-

import sys
import socket
import select


def server_udp(addr):

    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sck.bind(addr)

    while True:

        try:
            rr, _rw, _re = select.select([sck], [], [])
        except:
            pass
        else:
            for conn in rr:
                data, origin = conn.recvfrom(4096)
                data = "Echo <" + data + ">"
                conn.sendto(data, origin)
                sys.stdout.write("%s\n" % data)

if __name__ == '__main__':

    try:
        host = ('', int(sys.argv[1]))
    except:
        host = ('', 4711)

    server_udp(host)
