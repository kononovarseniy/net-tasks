import zmq
import sys

port = sys.argv[1]

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:{0}".format(port))

while True:
    msg = socket.recv_string()
    print("Received:", msg)
    socket.send_string("ar-server@{0}: {1}".format(port, msg))
