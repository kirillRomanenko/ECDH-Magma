#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

// Размер блока для Магмы (8 байт)
const size_t BLOCK_SIZE = 8;
// Размер ключа для Магмы (32 байта)
const size_t KEY_SIZE = 32;

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Генерация ключевой пары ECDH
EVP_PKEY* generate_ecdh_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) handle_openssl_error();
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_openssl_error();
    
    // Устанавливаем кривую secp256k1
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)"secp256k1", 0);
    params[1] = OSSL_PARAM_construct_end();
    
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) handle_openssl_error();
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) handle_openssl_error();
    
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

// Выработка общего секрета
std::vector<unsigned char> derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pub_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) handle_openssl_error();
    
    if (EVP_PKEY_derive_init(ctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) handle_openssl_error();
    
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) handle_openssl_error();
    
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) handle_openssl_error();
    
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

// Шифрование данных алгоритмом Магма
std::vector<unsigned char> encrypt_magma(const std::vector<unsigned char>& plaintext,
                                        const std::vector<unsigned char>& key,
                                        size_t& block_count) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();
    
    // Устанавливаем алгоритм Магма (GOST 28147-89)
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "magma-cbc", nullptr);
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error();
    }
    
    // IV для CBC (8 байт для Магмы)
    std::vector<unsigned char> iv(EVP_CIPHER_get_iv_length(cipher));
    memset(iv.data(), 0, iv.size());
    
    if (EVP_EncryptInit_ex2(ctx, cipher, key.data(), iv.data(), nullptr) <= 0) {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error();
    }
    
    // Вычисляем размер буфера для шифротекста
    int ciphertext_len = plaintext.size() + EVP_CIPHER_get_block_size(cipher);
    std::vector<unsigned char> ciphertext(ciphertext_len);
    
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) <= 0) {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error();
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) <= 0) {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error();
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    
    // Подсчет блоков
    block_count = (plaintext.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ciphertext;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>\n";
        return EXIT_FAILURE;
    }
    
    // Инициализация OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, nullptr);
    
    try {
        // 1. Генерация ключей для двух сторон
        auto start = std::chrono::high_resolution_clock::now();
        
        std::cout << "Generating ECDH keys (secp256k1)...\n";
        EVP_PKEY* alice_key = generate_ecdh_key();
        EVP_PKEY* bob_key = generate_ecdh_key();
        
        // 2. Выработка общего секрета
        std::cout << "Deriving shared secret...\n";
        std::vector<unsigned char> alice_secret = derive_shared_secret(alice_key, bob_key);
        std::vector<unsigned char> bob_secret = derive_shared_secret(bob_key, alice_key);
        
        // Проверка, что секреты совпадают
        if (alice_secret != bob_secret) {
            std::cerr << "Error: Shared secrets don't match!\n";
            return EXIT_FAILURE;
        }
        
        // 3. Чтение файла
        std::cout << "Reading input file...\n";
        std::ifstream file(argv[1], std::ios::binary);
        if (!file) {
            std::cerr << "Error opening file: " << argv[1] << "\n";
            return EXIT_FAILURE;
        }
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> file_data(file_size);
        file.read(reinterpret_cast<char*>(file_data.data()), file_size);
        file.close();
        
        // 4. Шифрование данных
        std::cout << "Encrypting with Magma (GOST 28147-89)...\n";
        size_t block_count = 0;
        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> ciphertext = encrypt_magma(file_data, alice_secret, block_count);
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        
        // 5. Замер времени
        auto end = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start).count();
        
        // 6. Вывод результатов
        std::cout << "\nResults:\n";
        std::cout << "========================================\n";
        std::cout << "File size:          " << file_size << " bytes\n";
        std::cout << "Blocks processed:   " << block_count << "\n";
        std::cout << "Total time:         " << total_duration << " ms\n";
        std::cout << "Encryption time:    " << encrypt_duration << " ms\n";
        std::cout << "Encryption speed:   " 
                  << (file_size / (encrypt_duration / 1000.0) / 1024 / 1024) 
                  << " MB/s\n";
        std::cout << "========================================\n";
        
        // 7. Сохранение зашифрованных данных
        std::ofstream out_file("encrypted.bin", std::ios::binary);
        out_file.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
        out_file.close();
        
        std::cout << "Encrypted data saved to 'encrypted.bin'\n";
        
        // Освобождение ресурсов
        EVP_PKEY_free(alice_key);
        EVP_PKEY_free(bob_key);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}