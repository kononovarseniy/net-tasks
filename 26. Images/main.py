#from scapy.config import conf
#conf.ipv6_enabled = False
from scapy.all import sniff
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6
import time
import os

hdr_content_length = b'Content-Length'
hdr_content_type = b'Content-Type'

class TCPstream:
    def __init__(self, src, dport, stream_id):
        self.src = src
        self.dport = dport
        self.data = b''
        self.ignore_bytes = 0
        self.waiting = False
        self.wait_bytes = 0
        self.seq_start = None
        self.offset = None
        self.stream_id = stream_id

    def log(self, msg):
        print("stream #{0}: {1}".format(self.stream_id, msg))

    def wait(self, cnt):
        self.waiting = True
        self.wait_bytes = cnt

    def is_ready(self):
        if self.ignore_bytes > 0:
            l = min(self.ignore_bytes, len(self.data))
            self.ignore_bytes -= l;
            if self.waiting > 0:
                self.wait_bytes -= l;
            self.data = self.data[l:]

        if self.ignore_bytes > 0:
            return False

        if self.waiting and self.wait_bytes > len(self.data):
            return False
        self.waiting = False
        return True


    def handle_packet(self, packet):
        if packet.flags.R or packet.flags.F:
            streams.remove(self)
            self.log("closed")
            return
        if packet.flags.S:
            self.seq_start = packet.seq + 1
            self.offset = 0
            self.log("SYN seq={0}".format(self.seq_start))
            return
        if not self.seq_start:
            self.seq_start = packet.seq
            self.offset = 0
            self.log("NO SYN seq={0}".format(self.seq_start))
        if packet.seq < self.seq_start:
            return;
        offset = packet.seq - self.seq_start
        if offset < 0: # Ignore packet
            return
        data = bytes(packet[TCP].payload)
        if offset > self.offset:
            self.log("skip [{0}, {1})".format(self.offset, offset))
            self.data += b'\0' * (offset - self.offset) + data
            self.offset = offset + len(data)
            return
        elif offset < self.offset:
            start = len(self.data) - (self.offset - offset)
            if start < 0: # Oops... Placeholder already consumed as payload
                return
            self.log("insert [{0}, {1})".format(offset, offset + len(data)))
            self.data = self.data[:start] + data + self.data[start + len(data):]
        else:
            self.data += data
            self.offset = self.offset + len(data);


id_counter = 0
streams = []  # array of TCPstream objects


def saveImage(stream, format_name, image):
    file_name = './img/' + str(time.time()) + '.' + format_name
    with open(file_name, 'wb') as file:
        stream.log("File {0} received!".format(file_name))
        file.write(image)
        file.close()


def handleStream(stream):
    while True:
        if not stream.is_ready():
            return

        data = stream.data
        http_start = data.find(b'HTTP/')
        # Bytes before HTTP are useless
        stream.ignore_bytes = http_start
        if http_start == -1:
            # Ignore all except few last bytes
            stream.ignore_bytes = len(data) - len(b'HTTP/')
            return # return to prevent infinite loop (some_bytes are not ignored)
        # Now we almost sure that content is HTTP header but it can be partially received
        # Find headers start
        headers_start = data.find(b'\r\n', http_start)
        if headers_start == -1:
            # Try again later with more data
            return
        headers_start += len(b'\r\n')

        # Find headers end
        headers_end = data.find(b'\r\n\r\n', headers_start)
        if headers_end == -1:
            # Try again later with more data
            return
        content_start = headers_end + len(b'\r\n\r\n')

        # Parse headers
        headers = data[headers_start:headers_end].split(b'\r\n')
        headers = map(lambda s: s.split(b': ', 1), filter(None, headers))
        headers = {key: value for key, value in headers}

        if (not hdr_content_length in headers) or (not hdr_content_type in headers):
            # Ignore HTTP header. And wait for the next header
            stream.ignore_bytes = content_start
            continue
        content_length = int(headers[hdr_content_length])
        content_type = headers[hdr_content_type].decode('ascii')

        if not content_type.startswith('image/'):
            # Ignore whole http response
            stream.ignore_bytes = content_start + content_length
            continue
        content_type = content_type[len('image/'):]

        if len(data) < content_start + content_length:
            stream.wait(content_start + content_length)
            stream.log("partial")
            return
        # Consume bytes
        image = data[content_start:content_start + content_length]
        saveImage(stream, content_type, image)
        stream.data = data[content_start + content_length:] 


def handlePacket(packet):
    global id_counter
    try:
        src = packet[IP].src
    except:
        src = packet[IPv6].src
    dport = packet[TCP].dport
    stream = None
    for s in streams:
        if src == s.src and dport == s.dport:
            stream = s
            break
    if not stream:
        stream = TCPstream(src, dport, id_counter)
        stream.log("new {0}:{1}".format(src, dport))
        streams.append(stream)
        id_counter += 1
    stream.handle_packet(packet[TCP])
    handleStream(stream)

try:
    if not os.path.exists('./img'):
        os.makedirs('./img');
except OSError:
    print("Cannot create directory")
else:
    print('Sniffing...')
    sniff(prn=handlePacket, filter='tcp port 80')
