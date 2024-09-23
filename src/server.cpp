#include <iostream>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

using websocketpp::connection_hdl;
using websocketpp::server;

typedef server<websocketpp::config::asio> ws_server;

ws_server echo_server;
std::unordered_map<std::string, std::pair<connection_hdl, std::string>>
    clients;  // Map public keys to client handles

void on_open(connection_hdl hdl) {
  std::cout << "Client connected." << std::endl;
}

void on_close(connection_hdl hdl) {
  std::cout << "Client disconnected." << std::endl;

  // Iterate over the map to find the matching connection handle
  for (auto it = clients.begin(); it != clients.end(); ++it) {
    if (it->second.first.lock() == hdl.lock()) {  // Compare connection handles
      std::cout << "Removing client with public key: " << it->first
                << std::endl;
      clients.erase(it);  // Remove the client from the map
      break;              // Exit the loop once the client is found and removed
    }
  }
  nlohmann::json client_update = {{"type", "client_update"},
                                  {"clients", nlohmann::json::array()}};
  for (const auto& client : clients) {
    client_update["clients"].push_back(client.first);
  }
  for (const auto& client : clients) {
    echo_server.send(client.second.first, client_update.dump(),
                     websocketpp::frame::opcode::text);
  }
}

void on_message(connection_hdl hdl,
                server<websocketpp::config::asio>::message_ptr msg) {
  auto payload = msg->get_payload();
  try {
    auto json = nlohmann::json::parse(payload);
    if (json["data"]["type"] == "hello") {
      std::string pub_key = json["data"]["public_key"];
      clients[pub_key].first = hdl;  // Store the client with their public key
      clients[pub_key].second =
          json["data"]["id"];  // Store the client with their public key

      std::cout << "Client connected with public key: " << pub_key << std::endl;
      std::cout << "Client connected with name: " << clients[pub_key].second
                << std::endl;
      // send a welcome message back to the client
      echo_server.send(hdl, "Welcome, " + clients[pub_key].second,
                       websocketpp::frame::opcode::text);

      // sending client_update message to all clients
      nlohmann::json client_update = {{"type", "client_update"},
                                      {"clients", nlohmann::json::array()}};
      for (const auto& client : clients) {
        client_update["clients"].push_back(client.first);
      }
      for (const auto& client : clients) {
        echo_server.send(client.second.first, client_update.dump(),
                         websocketpp::frame::opcode::text);
      }
    } else if (json["data"]["type"] == "chat") {
      // Handle other message types
      std::cout << "Received message: " << json["chat"]["message"] << std::endl;
    } else {
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
        echo_server.send(client.second.first, message,
                         websocketpp::frame::opcode::text);
        std::cout << "Sent to client with public key " << client.first << ": "
                  << message << std::endl;
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

  std::cout << "WebSocket server is running on ws://localhost:9002"
            << std::endl;

  // Start the server send loop in a separate thread
  std::thread send_thread(server_send_loop);

  echo_server.run();

  send_thread
      .join();  // Wait for the send thread to finish (it won't in this case)

  return 0;
}