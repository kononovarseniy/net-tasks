#include <zmq.hpp>
#include <iostream>
#include <string>

int main() {
    zmq::context_t context(1);
    zmq::socket_t socket(context, ZMQ_REQ);

    socket.connect("tcp://127.0.0.1:8083");
    socket.connect("tcp://127.0.0.1:8084");
    socket.connect("tcp://127.0.0.1:8085");

    for (;;) {
        std::string msg;
        std::cin >> msg;

        zmq::message_t req(msg.length());
        memcpy(req.data(), msg.c_str(), msg.length());
        socket.send(req);

        zmq::message_t reply;
        socket.recv(&reply);
        std::string rmsg((char *)reply.data(), reply.size());

        std::cout << "reply: " << rmsg << std::endl;
    }
    return 0;
}
