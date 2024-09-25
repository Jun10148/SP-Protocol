#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <iostream>

RSA* generateRSAKey() {
    int keyLength = 2048;
    unsigned long exponent = RSA_F4;  // Commonly used public exponent (65537)
    
    // Generate the RSA key
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, exponent);
    if (RSA_generate_key_ex(rsa, keyLength, bn, NULL) != 1) {
        std::cerr << "Error generating RSA key\n";
        RSA_free(rsa);
        BN_free(bn);
        return nullptr;
    }
    
    BN_free(bn);
    return rsa;
}

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

int main() {
    // Generate RSA key
    RSA* myRSA = generateRSAKey();
    
    if (myRSA) {
        std::cout << "Private Key:\n";
        std::cout << getPrivateKey(myRSA) << std::endl;
        
        // Clean up
        RSA_free(myRSA);
    }

    return 0;
}