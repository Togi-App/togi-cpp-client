// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Togi
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <chrono>
#include <ctime>
#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

const std::string API_BASE = "https://api.togi-app.com/api/v1";

const std::string API_KEY = "";
const std::string API_PASSWORD = "";
const std::string SECRET = ""; // Leave empty if no encryption is used

std::vector<unsigned char> encryptAes256Cbc(const std::string& plaintext,
                                            const std::vector<unsigned char>& key,
                                            const std::vector<unsigned char>& iv)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::string base64EncodeRaw(const unsigned char* input, int length)
{
    BIO* bmem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);

    // Write to BIO and flush
    BIO_write(b64, input, length);
    BIO_flush(b64);

    // Get the data from BIO
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    // Use the full length of the buffer
    std::string encoded(bptr->data, bptr->length);

    // Free BIO resources
    BIO_free_all(b64);
    return encoded;
}

std::vector<unsigned char> base64Decode(const std::vector<unsigned char>& input)
{
    BIO* bio = BIO_new_mem_buf(input.data(), input.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> output(input.size());
    int decoded_size = BIO_read(bio, output.data(), input.size());
    output.resize(decoded_size);
    BIO_free_all(bio);
    return output;
}

std::string getCurrTimeInMS()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    long long millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    return std::to_string(millis);
}

std::string createSignature(const std::string& password, const std::string& timestamp)
{
    // Generate the signature
    unsigned char* result;
    unsigned int len = 32;
    result = HMAC(EVP_sha256(), password.c_str(), password.length(),
                  reinterpret_cast<const unsigned char*>(timestamp.c_str()), timestamp.length(),
                  NULL, &len);
    std::string signature = base64EncodeRaw(result, len);

    return signature;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s)
{
    s->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string postJson(const std::string& url, const nlohmann::json& data)
{
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl)
    {
        std::string timestamp = getCurrTimeInMS();
        std::string signature = createSignature(API_PASSWORD, timestamp);

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("X-API-Key: " + API_KEY).c_str());
        headers = curl_slist_append(headers, ("X-Timestamp: " + timestamp).c_str());
        headers = curl_slist_append(headers, ("X-Signature: " + signature).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");

        std::string body = data.dump();

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    return response;
}

std::string getJson(const std::string& url)
{
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl)
    {
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("X-API-Key: " + API_KEY).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    return response;
}

void replaceLiteralSlashN(std::string& text)
{
    std::string from = "\\n";
    std::string to = "\n";
    size_t start_pos = 0;

    while ((start_pos = text.find(from, start_pos)) != std::string::npos)
    {
        text.replace(start_pos, from.length(), to);
        start_pos += to.length(); // move past the replacement
    }
}

int main()
{
    std::string report;

    std::cout << "/////////////////////////////////////////////////////////" << std::endl;
    std::cout << "//                                                     //" << std::endl;
    std::cout << "//  This is the Togi C++ client for posting reports    //" << std::endl;
    std::cout << "//  to a project created in the Togi app.              //" << std::endl;
    std::cout << "//                                                     //" << std::endl;
    std::cout << "/////////////////////////////////////////////////////////" << std::endl;

    std::cout << "Enter report: ";
    std::getline(std::cin, report);
    replaceLiteralSlashN(report);

    // Use timestamp as ID
    std::string id = std::to_string(std::time(nullptr));

    // Check whether to encrypt
    nlohmann::json payload;
    if (SECRET.empty())
    {
        // Create the payload directly
        payload = { { "id", id }, { "report", { { "description", report } } } };
    }
    else
    {
        // Create the report json
        nlohmann::json report_json = {
            { "description", report },
        };

        // Convert report json to string
        std::string report_str = report_json.dump();

        // Create an iv for encryption
        std::vector<unsigned char> iv(16);
        RAND_bytes(iv.data(), iv.size());

        // Encrypt the report json
        std::vector<unsigned char> app_secret(SECRET.begin(), SECRET.end());
        app_secret = base64Decode(app_secret);
        std::vector<unsigned char> encrypted = encryptAes256Cbc(report_str, app_secret, iv);

        // Combine iv and encrypted json
        std::vector<unsigned char> combined;
        combined.insert(combined.end(), iv.begin(), iv.end());
        combined.insert(combined.end(), encrypted.begin(), encrypted.end());

        // Encod the data
        std::string encrypted_base64 = base64EncodeRaw(combined.data(), combined.size());

        // Create the payload
        payload = { { "id", id }, { "report", encrypted_base64 } };
    }

    std::cout << "\nSending report..." << std::endl;
    std::string res = postJson(API_BASE + "/report", payload);
    std::cout << "Response: " << res << "\n" << std::endl;

    return 0;
}
