#include <zmq.hpp>
#include <iostream>
#include <string>

int main() {
    zmq::context_t context(1);
    zmq::socket_t socket(context, ZMQ_REQ);

    socket.connect("tcp://127.0.0.1:8081");
    socket.connect("tcp://127.0.0.1:8082");
    socket.connect("tcp://127.0.0.1:8083");

    for (;;) {
        std::string msg;
        std::cout << ">>> ";
        std::cin >> msg;

        zmq::message_t req(msg.length());
        memcpy(req.data(), msg.c_str(), msg.length());
        socket.send(req);

        zmq::message_t reply;
        socket.recv(&reply);
        std::string rmsg((char *)reply.data(), reply.size());

        std::cout << rmsg << std::endl;
    }
    return 0;
}
