#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <thread>
#include <set>
#include <unordered_map>

using websocketpp::connection_hdl;
using websocketpp::server;

typedef server<websocketpp::config::asio> ws_server;

ws_server echo_server;
std::unordered_map<std::string, std::pair<connection_hdl, std::string>> clients; // Map public keys to client handles

void on_open(connection_hdl hdl) {
    std::cout << "Client connected." << std::endl;
}

void on_close(connection_hdl hdl) {
    std::cout << "Client disconnected." << std::endl;
    // Remove client from map based on public key (if you track that)
}

void on_message(connection_hdl hdl, server<websocketpp::config::asio>::message_ptr msg) {
    auto payload = msg->get_payload();
    try {
        auto json = nlohmann::json::parse(payload);
        if (json["data"]["type"] == "hello") {
            std::string client_name = json["data"]["id"];
            clients[client_name].first = hdl; // Store the client with their public key
            clients[client_name].second = json["data"]["public_key"]; // Store the client with their public key

            std::cout << "Client connected with name key: " << client_name << std::endl;
            std::cout << "Client connected with public key: " << clients[client_name].second << std::endl;
            // send a welcome message back to the client
            echo_server.send(hdl, "Welcome, " + client_name, websocketpp::frame::opcode::text);
        } else if(json["data"]["type"] == "chat"){
            // Handle other message types
            std::cout << "Received message: " << json["chat"]["message"] << std::endl;
        } else{
            std::cout << "Received message: " << payload << std::endl;
        }
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    }
}

void server_send_loop() {
    std::string message;
    while (true) {
        std::cout << "Enter a message to send to all clients: ";
        std::getline(std::cin, message);
        if (!message.empty()) {
            for (const auto& client : clients) {
                echo_server.send(client.second.first, message, websocketpp::frame::opcode::text);
                std::cout << "Sent to client with public key " << client.first << ": " << message << std::endl;
            }
        }
    }
}

int main() {

    echo_server.clear_access_channels(websocketpp::log::alevel::all);
    echo_server.clear_error_channels(websocketpp::log::elevel::all);
    
    echo_server.set_open_handler(&on_open);
    echo_server.set_close_handler(&on_close);
    echo_server.set_message_handler(&on_message);

    echo_server.init_asio();
    echo_server.set_reuse_addr(true);
    echo_server.listen(9002);
    echo_server.start_accept();

    std::cout << "WebSocket server is running on ws://localhost:9002" << std::endl;

    // Start the server send loop in a separate thread
    std::thread send_thread(server_send_loop);
    
    echo_server.run();
    
    send_thread.join(); // Wait for the send thread to finish (it won't in this case)
    
    return 0;
}