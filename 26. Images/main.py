from scapy.all import sniff
from scapy.layers.inet import TCP, IP
import time
import os

hdr_content_length = b'Content-Length'
hdr_content_type = b'Content-Type'

class TCPstream:
    def __init__(self, src, dport, data):
        self.src = src
        self.dport = dport
        self.data = data
        self.ignore_bytes = 0
        self.waiting = False
        self.wait_bytes = 0

    def wait(self, cnt):
        self.waiting = True
        self.wait_bytes = cnt


streams = []  # array of TCPstream objects


def saveImage(src, format_name, image):
    file_name = 'img/' + str(time.time()) + '.' + format_name
    with open(file_name, 'wb') as file:
        print('File ', file_name, 'created!')
        file.write(image)
        file.close()


def handleStream(stream):
    while True:
        if stream.ignore_bytes > 0:
            l = min(stream.ignore_bytes, len(stream.data))
            stream.ignore_bytes -= l;
            if stream.waiting > 0:
                stream.wait_bytes -= l;
            stream.data = stream.data[l:]

        if stream.ignore_bytes > 0:
            return;

        if stream.waiting and stream.wait_bytes > len(stream.data):
            return
        stream.waiting = False

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
        headers = filter(None, headers)
        headers = {key: value for key, value in map(lambda s: s.split(b': ', 1), headers)}

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
            print("Partial")
            return
        # Consume bytes
        image = data[content_start:content_start + content_length]
        saveImage(stream.src, content_type, image)
        stream.data = data[content_start + content_length:] 


def handlePacket(packet):
    src = packet[IP].src
    dport = packet[TCP].dport
    data = bytes(packet[TCP].payload)
    found = False
    for stream in streams:
        if src == stream.src and dport == stream.dport:
            stream.data += data
            found = True
            break
    if not found:
        print("New stream", src, dport)
        stream = TCPstream(src, dport, data)
        streams.append(stream)
    handleStream(stream)

try:
    if not os.path.exists('./img'):
        os.makedirs('./img');
except OSError:
    print("Cannot create directory")
else:
    print('Sniffing...')
    sniff(prn=handlePacket, filter='tcp port 80')
