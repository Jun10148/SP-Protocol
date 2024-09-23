#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

using websocketpp::connection_hdl;
using websocketpp::server;

typedef server<websocketpp::config::asio> ws_server;

ws_server echo_server;

void on_open(connection_hdl hdl) {
    std::string message = "Hello from the server!";
    echo_server.send(hdl, message, websocketpp::frame::opcode::text);
    std::cout << "Sent to client: " << message << std::endl;
}

void on_message(connection_hdl, server<websocketpp::config::asio>::message_ptr msg) {
    std::cout << "Received from client: " << msg->get_payload() << std::endl;
}

int main() {
    echo_server.set_open_handler(&on_open);
    echo_server.set_message_handler(&on_message);
    
    echo_server.init_asio();
    echo_server.set_reuse_addr(true);
    echo_server.listen(9002);
    echo_server.start_accept();
    
    std::cout << "WebSocket server is running on ws://localhost:9002" << std::endl;

    echo_server.run();
    
    return 0;
}