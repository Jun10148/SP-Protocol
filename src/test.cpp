#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
using namespace std;

std::string sha256(const std::string& data) {
    cout <<"public key: " << data << endl;
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

std::string base64Encode(const std::string &input) {
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

int main() {
  // Hard-coded message
  std::string message = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3uYa9ZTguG41RFEK8rhG\neV690Mdji/LyLtP26vuykMPYVUY78K0VRzPBDL3DnZPDw5E3GoyvpQoFc4gL+YwE\nGS6Of6TPYSU4jR2oL+6pkgiAGQk1MblLlHEZixRoirQ7k01w7FLuNnmBi4xKn+++\nsEi0XG7nE24vZjLb/N8f4F9y6UVIypxd8O8Xgm1DH9BLIEuM17LhxQkXTT60hOQ+\nIUVY1PGmy/NrhSSMPuPR4dv9F7iU8iDMJCdoCN2hFW2HF3JozFAPuPVDTxYhudzf\nHdW0j3997H6LPz7o78ah/PuMvxqgTHK20fvxwGV+9l3+rIgSUknUy5lV1nZu4Vb8\nhQIDAQAB\n-----END PUBLIC KEY-----\n";

  cout << sha256(message) << endl;;
  cout <<base64Encode(sha256(message)) << endl;
  return 0;
}
