import os, textwrap
import netifaces

RESP_PORT = 2666
SERVER_PORT = 2666
INITIATOR = '\x1b[35minitiator\x1b[0m'
RESPONDER = '\x1b[34mresponder\x1b[0m'
SERVER = '\x1b[31mserver\x1b[0m'
DEBUG = bool(os.environ.get('WLSK_DEBUG', False))

def get_local_address():
    ifaces = netifaces.interfaces()
    if 'docker0' in ifaces:
        iface = 'docker0'
    elif 'enp0s25' in ifaces:
        iface = 'enp0s25'
    else:
        iface = 'eth0'
    return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

if DEBUG:
    def debug(message):
        print('\x1b[37m{}\x1b[0m'.format(textwrap.indent(message, '  ')))
else:
    def debug(message):
        pass

