#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

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

RSA* generateRSAKey() {
  RSA* newrsa = RSA_generate_key(2048, 65537, nullptr, nullptr);
  if (!newrsa) {
    std::cerr << "Failed to generate RSA key" << std::endl;
    return nullptr;
  }
  return newrsa;
}

//new ver by chatgpt
std::string getPublicKey(RSA* rsa) {
    if (rsa == nullptr) {
        std::cerr << "RSA key is null" << std::endl;
        return "";
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "Failed to create BIO" << std::endl;
        return "";
    }

    if (!PEM_write_bio_RSA_PUBKEY(bio, rsa)) {
        std::cerr << "Failed to write public key" << std::endl;
        BIO_free(bio);
        return "";
    }

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free(bio);

    if (bufferPtr == nullptr) {
        std::cerr << "Failed to get memory pointer" << std::endl;
        return "";
    }

    return std::string(bufferPtr->data, bufferPtr->length);
}
//chatgpt
std::string getPrivateKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());  // Create a memory BIO

    // Write the private key to a memory BIO in PEM format
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    // Get the data from the BIO
    char* keyBuffer = NULL;
    long keyLength = BIO_get_mem_data(bio, &keyBuffer);

    // Copy the private key into a std::string
    std::string privateKey(keyBuffer, keyLength);

    // Free the BIO memory
    BIO_free(bio);

    return privateKey;  // Return the private key as a string
}


std::string sha256(const std::string& data) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
         hash);

  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(hash[i]);
  }
  return ss.str();
}

// written by chatgpt (checked if it works with openssl command output vs this)
std::string base64Encode(const std::string& input) {
  static const std::string base64Chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "0123456789+/";

  std::string output;
  int i = 0;
  unsigned char array3[3];
  unsigned char array4[4];

  for (size_t j = 0; j < input.size(); j++) {
    array3[i++] = input[j];
    if (i == 3) {
      array4[0] = (array3[0] & 0xfc) >> 2;
      array4[1] = ((array3[0] & 0x03) << 4) + ((array3[1] & 0xf0) >> 4);
      array4[2] = ((array3[1] & 0x0f) << 2) + ((array3[2] & 0xc0) >> 6);
      array4[3] = array3[2] & 0x3f;

      for (i = 0; (i < 4); i++) {
        output += base64Chars[array4[i]];
      }
      i = 0;
    }
  }

  if (i) {
    for (int j = i; j < 3; j++) {
      array3[j] = '\0';
    }

    array4[0] = (array3[0] & 0xfc) >> 2;
    array4[1] = ((array3[0] & 0x03) << 4) + ((array3[1] & 0xf0) >> 4);
    array4[2] = ((array3[1] & 0x0f) << 2) + ((array3[2] & 0xc0) >> 6);
    array4[3] = array3[2] & 0x3f;

    for (int j = 0; j < i + 1; j++) {
      output += base64Chars[array4[j]];
    }

    while ((i++ < 3)) {
      output += '=';
    }
  }

  return output;
}

std::string getPublicKeyFingerprint(RSA* rsa) {
  // Convert RSA public key to PEM format
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSA_PUBKEY(bio, rsa);

  // Get the PEM formatted public key
  char* pemData;
  long pemLength = BIO_get_mem_data(bio, &pemData);
  std::string publicKeyPem(pemData, pemLength);

  // Compute the SHA-256 fingerprint
  std::string fingerprint = sha256(publicKeyPem);

  // Clean up
  BIO_free(bio);

  return fingerprint;
}

void on_open(connection_hdl hdl) {
  std::cout << "Connection established with server." << std::endl;
  client_hdl = hdl;

  // Generate RSA key pair
  myRSA = generateRSAKey();
  std::string public_key;
  std::string private_key;
  if (myRSA) {
    public_key = getPublicKey(myRSA);
    private_key = getPrivateKey(myRSA);
  } else {
    cout << "error: couldnt generate rsa key" << endl;
  }

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
    } else if (json["data"]["type"] == "public_chat"){
        cout << "public chat from: " << json["data"]["sender"] << endl;
        cout << json["data"]["message"] << endl;
    } 
    else {
      // std::cout << "Received message: " << payload << std::endl;
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

        if (first_word == "send_message") {
          unsigned char aesKey[32];
          unsigned char iv[16];
          RAND_bytes(aesKey, sizeof(aesKey));
          RAND_bytes(iv, sizeof(iv));

          client_instance.send(client_hdl, "sup",
                               websocketpp::frame::opcode::text);
        } else if (first_word == "public_chat") {
          nlohmann::json public_chat;
          public_chat["data"]["type"] = "public_chat";

          std::string fingerprint = getPublicKeyFingerprint(myRSA);
          fingerprint = base64Encode(fingerprint);
          public_chat["data"]["sender"] = fingerprint;

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

          string plain_signature =
              public_chat["data"].dump() + to_string(counter);
          public_chat["signature"] = base64Encode(plain_signature); //not a real signature

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