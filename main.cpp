//
//  main.cpp
//  testExcelProtect
//
//  Created by Ole Kristian Ek Hornnes on 26/01/2025.
//

#include <iostream>

#include <iostream>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h> // For Base64 encoding/decoding
#include <openssl/buffer.h> // Required for BUF_MEM
#include <iomanip>
#include <sstream>

// Helper function: Convert integer to 4-byte little-endian representation
std::vector<unsigned char> int_to_little_endian(int value) {
    std::vector<unsigned char> result(4);
    result[0] = value & 0xFF;
    result[1] = (value >> 8) & 0xFF;
    result[2] = (value >> 16) & 0xFF;
    result[3] = (value >> 24) & 0xFF;
    return result;
}

// Helper function: Base64 decode
std::vector<unsigned char> base64_decode(const std::string& encoded) {
    std::vector<unsigned char> decoded;
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int len = encoded.size();
    decoded.resize(len);
    len = BIO_read(bio, decoded.data(), len);
    decoded.resize(len);
    BIO_free_all(bio);

    return decoded;
}

// Helper function: Base64 encode
std::string base64_encode(const std::vector<unsigned char>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string encoded(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return encoded;
}

// Helper function: Convert string to UTF-16LE
std::vector<unsigned char> to_utf16le(const std::string& str) {
    std::vector<unsigned char> utf16le;
    for (char c : str) {
        utf16le.push_back(static_cast<unsigned char>(c)); // Low byte
        utf16le.push_back(0);                            // High byte (UTF-16LE encoding)
    }
    return utf16le;
}

// Function to compute SHA-512 hash
std::vector<unsigned char> sha512_hash(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA512_DIGEST_LENGTH);
    SHA512(data.data(), data.size(), hash.data());
    return hash;
}

// Helper function: Combine two byte vectors
std::vector<unsigned char> combine(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    std::vector<unsigned char> result = a;
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

// Function to reproduce Excel password hashing
void reproduce_excel_hash(const std::string& password, const std::string& saltBase64, int spinCount, const std::string& expectedHashBase64) {
    // Decode the salt from Base64
    std::vector<unsigned char> salt = base64_decode(saltBase64);

    // Convert password to UTF-16LE
    std::vector<unsigned char> utf16lePassword;
    for (char c : password) {
        utf16lePassword.push_back(static_cast<unsigned char>(c)); // Low byte
        utf16lePassword.push_back(0);                            // High byte
    }

    // Combine salt and UTF-16LE password
    std::vector<unsigned char> combined = combine(salt, utf16lePassword);

    // Compute the initial hash
    std::vector<unsigned char> hash = sha512_hash(combined);

    // Perform spinCount iterations with loop counter
    for (int i = 0; i < spinCount; ++i) {
        // Convert the counter to 4-byte little-endian
        std::vector<unsigned char> counterLE = int_to_little_endian(i);

        // Combine the hash and counter
        std::vector<unsigned char> combinedHash = combine(hash, counterLE);

        // Compute the new hash
        hash = sha512_hash(combinedHash);
    }

    // Encode the final hash in Base64
    std::string finalHashBase64 = base64_encode(hash);

    // Output the results
    std::cout << "Reproduced Hash: " << finalHashBase64 << std::endl;
    if (finalHashBase64 == expectedHashBase64) {
        std::cout << "Match with Excel's hash!" << std::endl;
    } else {
        std::cout << "No match with Excel's hash!" << std::endl;
    }
}

int main() {
    // Debugging example
    std::string password = "dole";
    std::string saltBase64 = "HwUHlVDHY2tAT5VGdF/hWw==";
    std::string hashBase64 = "TxexuSWgkCxqVnKSnRLh73n4sSp/GEGMXK09Hk3Qq/+mLXCcCdShsmSbXmVYmsOyLs9vXF7s3tZQQQAGdG/9kA==";
    int spinCount = 100000; // 100000

    reproduce_excel_hash(password, saltBase64, spinCount, hashBase64);

    return 0;
}
