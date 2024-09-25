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

class Client {
 public:
  std::string client_id;
  std::string public_key;
  connection_hdl client_hdl;

  Client(const std::string& client_id, const std::string& public_key,
         connection_hdl hdl)
      : client_id(client_id), public_key(public_key), client_hdl(hdl) {}
};
class Server {
 public:
  std::string address;
  std::string server_id;
  std::vector<Client> clients;

  Server(const std::string& address, const std::string& server_id)
      : address(address), server_id(server_id) {}

  // Add a client to the server
  void add_client(const Client& client) { clients.push_back(client); }
};

std::vector<Server> server_list;

ws_server echo_server;
// std::unordered_map<std::string, std::pair<connection_hdl, std::string>>
//  clients;  // Map public keys to client handles
void update(connection_hdl hdl) {
    // Initialize the client_update JSON object
    nlohmann::json client_update = {{"type", "client_update"},
                                     {"clients", nlohmann::json::array()}};

    // Iterate through clients and add their information to the JSON array
    for (const auto& client : server_list[0].clients) {
        // Create a JSON object for the client
        nlohmann::json client_info = {
            {"client-id", client.client_id},      // Assuming client_id is a member of the client structure
            {"public-key", client.public_key}     // Assuming public_key is also a member of the client structure
        };

        // Add the client info to the clients array
        client_update["clients"].push_back(client_info);
    }

    // Send the update to all clients in all servers
    for (const auto& server : server_list) {
        for (const auto& client : server.clients) {
            echo_server.send(client.client_hdl, client_update.dump(),
                             websocketpp::frame::opcode::text);
        }
    }
}

void on_open(connection_hdl hdl) {
  std::cout << "Client connected." << std::endl;
}

void on_close(connection_hdl hdl) {
  std::cout << "Client disconnected." << std::endl;
  server_list[0].clients.erase(std::remove_if(server_list[0].clients.begin(),
                                              server_list[0].clients.end(),
                                              [&hdl](const Client& c) {
                                                return hdl.lock() ==
                                                       c.client_hdl.lock();
                                              }),
                               server_list[0].clients.end());
  update(hdl);
}

void on_message(connection_hdl hdl,
                server<websocketpp::config::asio>::message_ptr msg) {
  auto payload = msg->get_payload();
  try {
    auto json = nlohmann::json::parse(payload);
    if (json["data"]["type"] == "hello") {
      std::string pub_key = json["data"]["public_key"];
      std::string client_id = json["data"]["id"];
      server_list[0].clients.push_back(Client(client_id, pub_key, hdl));
      std::cout << "Client connected with public key: "
                << server_list[0].clients.back().public_key << std::endl;
      std::cout << "Client connected with name: "
                << server_list[0].clients.back().client_id << std::endl;
      // send a welcome message back to the client
      // prints error message on client because message isnt json
      echo_server.send(hdl,
                       "Welcome, " + server_list[0].clients.back().client_id,
                       websocketpp::frame::opcode::text);
      update(hdl);

    } else if (json["data"]["type"] == "chat") {
      // Handle other message types
      std::cout << "Received message: " << json["chat"]["message"] << std::endl;
    } else if (json["type"] == "client_list_request") {
      // sending client_list message to all clients
      nlohmann::json client_update = {{"type", "client_list"},
                                      {"servers", nlohmann::json::array()}};

      // Iterate over servers to populate JSON
      for (const auto& server : server_list) {
        nlohmann::json server_json = {{"address", server.address},
                                      {"server-id", server.server_id},
                                      {"clients", nlohmann::json::array()}};

        for (const auto& client : server.clients) {
          nlohmann::json client_json = {{"client-id", client.client_id},
                                        {"public-key", client.public_key}};
          server_json["clients"].push_back(client_json);
        }

        client_update["servers"].push_back(server_json);
      }

      for (const auto& client : server_list[0].clients) {
        echo_server.send(client.client_hdl, client_update.dump(),
                         websocketpp::frame::opcode::text);
      }
    } else if (json["data"]["type"] == "public_chat") {
      std::cout << "public chat received" << std::endl;
      for (const auto& server : server_list) {
        for (const auto& client : server.clients) {
          echo_server.send(client.client_hdl, json.dump(),
                           websocketpp::frame::opcode::text);
        }
      }
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
    /*
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
    */
  }
}

int main() {
  server_list.push_back(Server("localhost", "server-001"));
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