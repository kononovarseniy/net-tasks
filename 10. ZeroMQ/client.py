import zmq

context = zmq.Context()
socket = context.socket(zmq.REQ)

socket.connect("tcp://127.0.0.1:8083")
socket.connect("tcp://127.0.0.1:8084")
socket.connect("tcp://127.0.0.1:8085")

while True:
    msg = input(">>> ");
    socket.send_string(msg);
    print(socket.recv_string());
