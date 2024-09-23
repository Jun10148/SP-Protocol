#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>

using websocketpp::client;
using websocketpp::connection_hdl;

typedef client<websocketpp::config::asio_client> ws_client;

ws_client client_instance;

void on_open(connection_hdl hdl) {
    std::string message = "Hello from the client!";
    client_instance.send(hdl, message, websocketpp::frame::opcode::text);
    std::cout << "Sent to server: " << message << std::endl;
}

void on_message(connection_hdl, client<websocketpp::config::asio_client>::message_ptr msg) {
    std::cout << "Received from server: " << msg->get_payload() << std::endl;
}

int main() {
    client_instance.init_asio();

    client_instance.set_open_handler(&on_open);
    client_instance.set_message_handler(&on_message);

    websocketpp::lib::error_code ec;
    ws_client::connection_ptr con = client_instance.get_connection("ws://localhost:9002", ec);
    
    if (ec) {
        std::cout << "Connect initialization error: " << ec.message() << std::endl;
        return 1;
    }

    client_instance.connect(con);
    client_instance.run();


    return 0;
}