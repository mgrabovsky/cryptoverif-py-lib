import netifaces

INITIATOR = '\x1b[31minitiator\x1b[0m'
RESPONDER = '\x1b[34mresponder\x1b[0m'
SERVER = '\x1b[35mserver\x1b[0m'
PORT = 2666

def get_local_address():
    return netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr']

