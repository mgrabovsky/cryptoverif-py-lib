import netifaces

INITIATOR = '\x1b[31minitiator\x1b[0m'
RESPONDER = '\x1b[34mresponder\x1b[0m'
SERVER = '\x1b[35mserver\x1b[0m'
PORT = 2666

def get_local_address():
    ifaces = netifaces.interfaces()
    if 'enp0s25' in ifaces:
        iface = netifaces.ifaddresses('enp0s25')
    else:
        iface = netifaces.ifaddresses('eth0')
    return iface[netifaces.AF_INET][0]['addr']

