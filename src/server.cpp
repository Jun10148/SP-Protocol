#include <fstream>
#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/server.hpp>

using websocketpp::client;
using websocketpp::connection_hdl;
using websocketpp::server;
using namespace std;

typedef server<websocketpp::config::asio> ws_server;
typedef websocketpp::client<websocketpp::config::asio_client> ws_client;



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
  connection_hdl server_hdl;

  Server(const std::string& address, const std::string& server_id)
      : address(address), server_id(server_id) {}

  // Add a client to the server
  void add_client(const Client& client) { clients.push_back(client); }
};

std::vector<Server> server_list;

ws_server echo_server;

int server_counter = 1;
string address = "placeholder";
void on_client_open(connection_hdl hdl) {
  server_list.push_back(Server("placeholder", to_string(server_counter)));
  server_list[server_list.size() - 1].server_hdl = hdl;
  cout << "connection open" << endl;
}

void on_client_message(connection_hdl hdl,
                       client<websocketpp::config::asio>::message_ptr msg) {
  auto payload = msg->get_payload();
  std::cout << "Received message from another server: " << payload << std::endl;
}

void connect_to_server(const std::string& serveraddr) {
  ws_client client_;
  client_.init_asio();
  client_.set_message_handler(&on_client_message);
  client_.set_open_handler(&on_client_open);

  std::string uri = "ws://" + serveraddr;

  try {
    websocketpp::lib::error_code ec;
    ws_client::connection_ptr con = client_.get_connection(uri, ec);

    if (ec) {
      std::cerr << "Could not create connection because: " << ec.message()
                << std::endl;
      return;
    }

    client_.connect(con);
    client_.run();  // Run the client in the same thread

    std::cout << "Connected to server at " << uri << std::endl;

  } catch (const std::exception& e) {
    std::cerr << "Error connecting to server: " << e.what() << std::endl;
  }
}

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
        {"client-id", client.client_id},   // Assuming client_id is a member of
                                           // the client structure
        {"public-key", client.public_key}  // Assuming public_key is also a
                                           // member of the client structure
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
      nlohmann::json client_welcome = {{"type", "client_id"}};
      client_welcome["data"]["type"] = "Welcome";
      client_welcome["client_id"] = server_list[0].clients.back().client_id;
      echo_server.send(hdl, client_welcome.dump(),
                       websocketpp::frame::opcode::text);
      update(hdl);

    } else if (json["type"] == "init") {
      bool exists = false;
      for (const auto& client : server_list[0].clients) {
        if (json["name"] == client.client_id) {
          exists = true;
          break;
        }
      }
      nlohmann::json reply;
      reply["type"] = "init";
      if (exists) {
        reply["result"] = "exists";
      } else {
        reply["result"] = "doesnt exist";
      }
      echo_server.send(hdl, reply.dump(), websocketpp::frame::opcode::text);
    } else if (json["data"]["type"] == "chat") {
      // Handle other message types
      for (const auto& server : server_list) {
        for (const auto& client : server.clients) {
          echo_server.send(client.client_hdl, json.dump(),
                           websocketpp::frame::opcode::text);
        }
      }
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
      client_update["user"] = json["user"];
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

    for (int i = 0; i < server_list.size(); i++) {
      if (i != 0) {
        echo_server.send(server_list[i].server_hdl, json.dump(),
                         websocketpp::frame::opcode::text);
      }
    }
    std::cout << "Received message: " << payload << std::endl;
  } catch (const nlohmann::json::parse_error& e) {
    std::cerr << "JSON parse error: " << e.what() << std::endl;
  }
}

void server_send_loop() {
  std::string message;
  while (true) {
    std::cout << "Enter serverip:port to connect to or type 'exit' to quit: ";
    std::getline(std::cin, message);
    if (!message.empty()) {
      if (message == "exit") {
        exit(1);
      }
      connect_to_server(message);
    }
  }
}

int main() {
  server_list.push_back(Server("localhost", "server1"));
  echo_server.clear_access_channels(websocketpp::log::alevel::all);
  echo_server.clear_error_channels(websocketpp::log::elevel::all);

  echo_server.set_open_handler(&on_open);
  echo_server.set_close_handler(&on_close);
  echo_server.set_message_handler(&on_message);

  echo_server.init_asio();
  echo_server.set_reuse_addr(true);
  echo_server.listen(boost::asio::ip::tcp::v4(), 9002);
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