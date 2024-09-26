#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <iostream>
#include <cstdlib>
int main() {
    // Specify the filenames for the private and public keys
    std::string username = "1";
    std::string privateKeyFile = "private_key-" + username + ".pem";
    std::string publicKeyFile = "public_key-" + username + ".pem";

    // Construct the OpenSSL command for generating the private key
    std::string genPrivateKeyCmd = "openssl genpkey -algorithm RSA -out " + privateKeyFile + 
                                   " -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537";

    // Call the command using system()
    int result = system(genPrivateKeyCmd.c_str());
    std::string genPublicKeyCmd = "openssl rsa -in " + privateKeyFile + " -pubout -out " + publicKeyFile;
    system(genPublicKeyCmd.c_str());

    return 0;
}