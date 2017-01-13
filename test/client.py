# -*- encoding: utf-8 -*-

import sys
import socket
import random
import time


def client_udp(addr):
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sck.connect(addr)

    for i in xrange(random.randint(5, 10)):
        sck.send('Hallo von %s (%d)' % (str(sck.getsockname()), i))
        data = sck.recv(4096)
        sys.stdout.write("%s\n" % data)
        time.sleep(random.randint(0, 3))

    sck.close()

if __name__ == '__main__':
    try:
        host, port = sys.argv[1].split(':')
    except:
        host, port = 'localhost', 4710

    client_udp((host, int(port)))
