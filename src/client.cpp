#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>

using namespace std;
using websocketpp::client;
using websocketpp::connection_hdl;

typedef client<websocketpp::config::asio_client> ws_client;

ws_client client_instance;
connection_hdl client_hdl;

std::string username;

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

std::string generate_rsa_key() {
  RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
  if (!rsa) {
    std::cerr << "Failed to generate RSA key" << std::endl;
    return "";
  }

  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(bio, rsa);
  BUF_MEM* buffer;
  BIO_get_mem_ptr(bio, &buffer);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_flush(bio);

  std::string public_key(buffer->data, buffer->length);
  BIO_free_all(bio);
  RSA_free(rsa);

  return public_key;
}

void on_open(connection_hdl hdl) {
  std::cout << "Connection established with server." << std::endl;
  client_hdl = hdl;

  // Generate RSA key pair
  std::string public_key = generate_rsa_key();

  nlohmann::json hello_message;
  hello_message["data"]["type"] = "hello";
  hello_message["data"]["public_key"] = public_key;
  hello_message["data"]["id"] = username;

  // Send the JSON message
  client_instance.send(client_hdl, hello_message.dump(),
                       websocketpp::frame::opcode::text);
}

void on_message(connection_hdl,
                client<websocketpp::config::asio_client>::message_ptr msg) {
  auto payload = msg->get_payload();
  try {
    auto json = nlohmann::json::parse(payload);
    if (json["type"] == "client_list") {
      server_list.clear();
      for (const auto& server_json : json["servers"]) {
        std::string address = server_json["address"];
        std::string server_id = server_json["server-id"];
        Server server(address, server_id);

        for (const auto& client_json : server_json["clients"]) {
          std::string client_id = client_json["client-id"];
          std::string public_key = client_json["public-key"];
          Client client(client_id, public_key, client_hdl);
          server.add_client(client);
        }

        server_list.push_back(server);
      }
      for (const auto& server : server_list) {
        cout << "users in server-id: " << server.server_id
             << " located at: " << server.address << endl;

        for (const auto& client : server.clients) {
          cout << client.client_id << endl;
        }

        server_list.push_back(server);
      }
    } else {
      std::cout << "Received message: " << payload << std::endl;
    }
  } catch (const nlohmann::json::parse_error& e) {
    std::cerr << "JSON parse error: " << e.what() << std::endl;
  }
}

void client_send_loop() {
  std::string message;
  while (true) {
    std::getline(std::cin, message);

    // Check if the connection handle is valid and not empty
    if (!message.empty() && client_hdl.lock()) {
      // If the user types "exit", close the connection and break the loop
      if (message == "exit") {
        std::cout << "Exiting..." << std::endl;
        client_instance.close(client_hdl, websocketpp::close::status::normal,
                              "Client closed connection");
        break;  // Exit the loop to stop the client
      } else {
        // Check if the first word is "chat"
        std::istringstream iss(message);
        std::string first_word;
        iss >> first_word;  // Extract the first word

        if (first_word == "chat") {
          cout << "sending a chat" << endl;
          nlohmann::json chat;
          chat["data"]["type"] = "chat";
          chat["chat"]["message"] = "hello lol";
          client_instance.send(client_hdl, chat.dump(),
                               websocketpp::frame::opcode::text);
        } else if (first_word == "clients") {
          cout << "requesting server for client list" << endl;
          nlohmann::json client_req;
          client_req["type"] = "client_list_request";
          client_instance.send(client_hdl, client_req.dump(),
                               websocketpp::frame::opcode::text);
        } else {
          // Otherwise, send the message to the server
          client_instance.send(client_hdl, message,
                               websocketpp::frame::opcode::text);
          std::cout << "Sent to server: " << message << std::endl;
        }
      }
    }
  }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    cout << "erroneous input" << endl;
    return 0;
  } else {
    username = argv[1];
  }
  // Disable logging
  client_instance.clear_access_channels(websocketpp::log::alevel::all);
  client_instance.clear_error_channels(websocketpp::log::elevel::all);

  client_instance.init_asio();
  client_instance.set_open_handler(&on_open);
  client_instance.set_message_handler(&on_message);

  websocketpp::lib::error_code ec;
  ws_client::connection_ptr con =
      client_instance.get_connection("ws://localhost:9002", ec);

  if (ec) {
    std::cout << "Connect initialization error: " << ec.message() << std::endl;
    return 1;
  }

  client_instance.connect(con);

  std::thread send_thread(client_send_loop);

  client_instance.run();
  send_thread.join();  // Wait for the send loop thread to finish
  return 0;
}