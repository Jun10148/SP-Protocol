#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>

using json = nlohmann::json;
using websocketpp::connection_hdl;
using websocketpp::client;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

// Define WebSocket client
typedef client<websocketpp::config::asio_client> websocket_client;

// WebSocket message handling
void on_message(websocket_client* c, connection_hdl hdl, websocketpp::config::asio_client::message_type::ptr msg) {
    std::cout << "Received message: " << msg->get_payload() << std::endl;
    // Parse JSON message
    auto json_msg = json::parse(msg->get_payload());

    // Process the "hello" message as an example
    if (json_msg["data"]["type"] == "hello") {
        std::cout << "Received hello message with public key: " << json_msg["data"]["public_key"] << std::endl;
    }
}

int main() {
    // Create a WebSocket client
    websocket_client client;

    try {
        client.init_asio();
        client.set_message_handler(bind(&on_message, &client, ::_1, ::_2));

        // Connect to the server
        std::string uri = "ws://localhost:9002";  // Adjust to your server's address
        websocketpp::lib::error_code ec;
        websocket_client::connection_ptr con = client.get_connection(uri, ec);

        if (ec) {
            std::cout << "Connection error: " << ec.message() << std::endl;
            return 1;
        }

        client.connect(con);

        // Example: Send a "hello" message
        json hello_msg = {
            {"data", {{"type", "hello"}, {"public_key", "example_public_key"}}}  // Dummy key for demonstration
        };

        client.send(con->get_handle(), hello_msg.dump(), websocketpp::frame::opcode::text);

        client.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}