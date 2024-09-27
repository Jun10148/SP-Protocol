#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
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
RSA* myRSA;
int counter = 0;

std::string privateKeyFile;
std::string publicKeyFile;
std::string publicKeyFingerprintFile;
std::string SignatureFile;
std::string bufferinFile;
std::string bufferoutFile;
std::string initialisationVectorFile;
std::string aesKeyFile;

std::string private_key;
std::string public_key;
std::string publicKeyFingerprint;
std::string signature;
std::string initialisationVector;
std::string aesKey;

int generate_keys() {
  // Construct the OpenSSL command for generating the private key
  std::string genPrivateKeyCmd =
      "openssl genpkey -algorithm RSA -out " + privateKeyFile +
      " -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537" +
      " > cache/NUL 2>&1";

  // Call the command using system()
  system(genPrivateKeyCmd.c_str());
  std::string genPublicKeyCmd = "openssl rsa -in " + privateKeyFile +
                                " -pubout -out " + publicKeyFile +
                                " > cache/NUL 2>&1";
  system(genPublicKeyCmd.c_str());

  return 0;
}

std::string readStringFromFile(const std::string& filename) {
  std::ifstream inFile(filename);
  std::stringstream buffer;

  if (inFile.is_open()) {
    buffer << inFile.rdbuf();  // Read file content into stringstream
    inFile.close();
    return buffer.str();  // Return the content as a string
  } else {
    std::cerr << "Error: Unable to open file for reading: " << filename
              << std::endl;
    return "";
  }
}

void writeStringToFile(const std::string& filename,
                       const std::string& content) {
  std::ofstream outFile(filename);

  if (outFile.is_open()) {
    outFile << content;
    outFile.close();
  } else {
    std::cerr << "Error: Unable to open file for writing: " << filename
              << std::endl;
  }
}

void getPublicKeyFingerprint() {
  std::string command = "openssl dgst -sha256 -binary " + publicKeyFile +
                        " | openssl base64 -out " + publicKeyFingerprintFile;
  // Execute the command
  system(command.c_str());
}

void signDataWithPSS() {
  // Step 1: Sign the data + counter with RSA-PSS and SHA-256
  std::string signCommand =
      "openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt "
      "rsa_pss_saltlen:32 -sign " +
      privateKeyFile + " -out cache/signature.bin cache/data_counter.txt";
  system(signCommand.c_str());

  // Step 2: Base64-encode the signature
  std::string base64EncodeCommand =
      "openssl base64 -in cache/signature.bin -out " + SignatureFile;
  system(base64EncodeCommand.c_str());
}

void on_open(connection_hdl hdl) {
  std::cout << "Connection established with server." << std::endl;
  client_hdl = hdl;

  nlohmann::json init;
  init["type"] = "init";
  init["name"] = username;
  // Send the JSON message
  client_instance.send(client_hdl, init.dump(),
                       websocketpp::frame::opcode::text);
}

void send_hello() {
  // Generate RSA key pair
  generate_keys();
  private_key = readStringFromFile(privateKeyFile);
  public_key = readStringFromFile(publicKeyFile);

  nlohmann::json hello_message;
  hello_message["data"]["type"] = "hello";
  hello_message["data"]["public_key"] = public_key;
  hello_message["data"]["id"] = username;
  hello_message["counter"] = counter;
  hello_message["type"] = "signed_data";

  string plain_signature = hello_message["data"].dump();
  plain_signature = plain_signature + to_string(counter);
  writeStringToFile("cache/data_counter.txt", plain_signature);
  signDataWithPSS();
  signature = readStringFromFile(SignatureFile);
  hello_message["signature"] = signature;

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
      }
    } else if (json["type"] == "init") {
      if (json["result"] == "exists") {
        cout << "The client name already exists, please choose another name"
             << endl;
        exit(1);
      } else {
        send_hello();
      }
    } else if (json["data"]["type"] == "public_chat") {
      std::string sender = json["data"]["sender"];
      std::string text = json["data"]["message"];
      for (const auto& server : server_list) {
        for (const auto& client : server.clients) {
          writeStringToFile(bufferinFile, client.public_key);
          std::string command = "openssl dgst -sha256 -binary " + bufferinFile +
                                " | openssl base64 -out " + bufferoutFile;
          system(command.c_str());
          std::string result = readStringFromFile(bufferoutFile);
          if (result == sender) {
            sender = client.client_id;
            break;
          }
        }
      }
      cout << "public chat from: " << sender << endl;
      cout << json["data"]["message"] << endl;
    } else if (json["data"]["type"] == "Welcome") {
      string myname = json["client_id"];
      cout << "Welcome client: " << myname << endl;
    } else if (json["data"]["type"] == "chat") {
      cout << json << endl;
    }
    if (username == "admin") {
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
    counter++;
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

        if (first_word == "send_message") {
          // generate aes IV
          std::string cmd =
              "openssl rand -base64 16 > " + initialisationVectorFile;
          system(cmd.c_str());

          cmd = "openssl rand -base64 32 > " + aesKeyFile;
          system(cmd.c_str());

          string word;
          vector<string> receivers;
          string last_word;
          while (iss >> word) {
            if (!last_word.empty()) {
              receivers.push_back(last_word);
            }
            last_word = word;
          }
          vector<string> servername;
          vector<string> receivername;
          for (const auto& receiver : receivers) {
            int it = 0;
            string first;
            string second;
            while (receiver[it] != '-' && it < receiver.length()) {
              first = first + receiver[it];
              it++;
            }
            it++;
            while (it < receiver.length()) {
              second = second + receiver[it];
              it++;
            }
            servername.push_back(first);
            receivername.push_back(second);
          }
          vector<string> pubkeys;

          for (const auto& server : server_list) {
            string receiving_server = server.server_id;
            for (const auto& client : server.clients) {
              string receiving_user = client.client_id;
              for (int i = 0; i < receivername.size(); i++) {
                if (receiving_server == servername[i] &&
                    receiving_user == receivername[i]) {
                  pubkeys.push_back(client.public_key);
                  break;
                }
              }
            }
          }
          nlohmann::json chat;
          vector<string> fingerprints;
          string msg;
          for (const auto& key : pubkeys) {
            writeStringToFile(bufferinFile, key);
            writeStringToFile(bufferoutFile, key);
            std::string cmd = "openssl dgst -sha256 -binary " + bufferinFile +
                              " | openssl base64 -out " + bufferoutFile;
            system(cmd.c_str());
            fingerprints.push_back(readStringFromFile(bufferoutFile));
          }
          chat["participants"] = fingerprints;

          string text = "";
          for (int i = 0; i < message.length(); i++) {
            if (message[i] == '"') {
              int j = i + 1;
              while (message[j] != '"' && j < message.length()) {
                text = text + message[j];
                j++;
              }
              break;
            }
          }
          chat["message"] = text;

          nlohmann::json priv_msg;
          priv_msg["data"]["type"] = "chat";
          priv_msg["data"]["chat"] = chat;
          priv_msg["data"]["client-info"]["client-id"] = username;
          priv_msg["data"]["client-info"]["server-id"] =
              server_list[0].server_id;

          client_instance.send(client_hdl, priv_msg.dump(),
                               websocketpp::frame::opcode::text);
        } else if (first_word == "public_chat") {
          nlohmann::json public_chat;
          public_chat["data"]["type"] = "public_chat";

          getPublicKeyFingerprint();
          publicKeyFingerprint = readStringFromFile(publicKeyFingerprintFile);
          public_chat["data"]["sender"] = publicKeyFingerprint;

          string text = "";
          for (int i = 0; i < message.length(); i++) {
            if (message[i] == '"') {
              int j = i + 1;
              while (message[j] != '"' && j < message.length()) {
                text = text + message[j];
                j++;
              }
              break;
            }
          }
          public_chat["data"]["message"] = text;

          public_chat["type"] = "signed_data";

          public_chat["counter"] = counter;

          string plain_signature = public_chat["data"].dump();
          plain_signature = plain_signature + to_string(counter);

          writeStringToFile("cache/data_counter.txt", plain_signature);

          signDataWithPSS();
          signature = readStringFromFile(SignatureFile);
          public_chat["signature"] = signature;

          client_instance.send(client_hdl, public_chat.dump(),
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
  privateKeyFile = "cache/private_key-" + username + ".pem";
  publicKeyFile = "cache/public_key-" + username + ".pem";
  publicKeyFingerprintFile =
      "cache/public_key_fingerprint-" + username + ".pem";
  SignatureFile = "cache/signature-" + username + ".pem";
  bufferinFile = "cache/buffer_in-" + username + ".pem";
  bufferoutFile = "cache/buffer_out-" + username + ".pem";
  initialisationVectorFile = "cache/iv-" + username + ".txt";
  aesKeyFile = "cache/aes_key-" + username + ".txt";
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