#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

// Use the WebSocket++ namespace
using websocketpp::connection_hdl;
using websocketpp::server;

// Define the server type
typedef server<websocketpp::config::asio> ws_server;

// Create a global server instance
ws_server echo_server;

// Function to send a JSON message when a client connects
void on_open(connection_hdl hdl) {
    // Create a JSON object
    nlohmann::json j;
    j["message"] = "Hello, WebSocket client!";
    
    // Convert JSON object to string
    std::string json_str = j.dump();
    
    // Send the message
    echo_server.send(hdl, json_str, websocketpp::frame::opcode::text);
    std::cout << "Sent: " << json_str << std::endl;
}

// Main function
int main() {
    // Set up the server
    echo_server.set_open_handler(&on_open);
    
    // Listen on port 9002
    echo_server.init_asio();
    echo_server.set_reuse_addr(true);
    echo_server.listen(9002);
    echo_server.start_accept();
    
    std::cout << "WebSocket server is running on ws://localhost:9002" << std::endl;

    // Start the ASIO io_service run loop
    echo_server.run();
    
    return 0;
}