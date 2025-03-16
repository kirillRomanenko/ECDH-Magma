#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <cstring>

// Размер блока для Магмы (64 бита)
#define BLOCK_SIZE 8

// Размер ключа для Магмы (256 бит)
#define KEY_SIZE 32

// Функция для вывода ошибок OpenSSL
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Таблица замен (S-блоки) для Магмы
const unsigned char SBOX[8][16] = {
    {0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
    {0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
    {0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
    {0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
    {0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
    {0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
    {0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
    {0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2}
};

// Функция для замены по S-блоку
unsigned char substitute(unsigned char value, int sboxIndex) {
    return SBOX[sboxIndex][value & 0xF];
}

// Основная функция шифрования Магма
void magma_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *key) {
    uint32_t left = (plaintext[0] << 24) | (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3];
    uint32_t right = (plaintext[4] << 24) | (plaintext[5] << 16) | (plaintext[6] << 8) | plaintext[7];

    for (int round = 0; round < 32; round++) {
        uint32_t roundKey = (key[(round % 8) * 4] << 24) | (key[(round % 8) * 4 + 1] << 16) |
                            (key[(round % 8) * 4 + 2] << 8) | key[(round % 8) * 4 + 3];

        uint32_t temp = right;
        right = left ^ (substitute((right + roundKey) & 0xFFFFFFFF, round % 8));
        left = temp;
    }

    ciphertext[0] = (right >> 24) & 0xFF;
    ciphertext[1] = (right >> 16) & 0xFF;
    ciphertext[2] = (right >> 8) & 0xFF;
    ciphertext[3] = right & 0xFF;
    ciphertext[4] = (left >> 24) & 0xFF;
    ciphertext[5] = (left >> 16) & 0xFF;
    ciphertext[6] = (left >> 8) & 0xFF;
    ciphertext[7] = left & 0xFF;
}

// Функция для шифрования блока данных в режиме CTR
void encryptBlockCTR(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *key, unsigned char *iv) {
    unsigned char encryptedCounter[BLOCK_SIZE];
    magma_encrypt(iv, encryptedCounter, key);

    for (int i = 0; i < BLOCK_SIZE; i++) {
        ciphertext[i] = plaintext[i] ^ encryptedCounter[i];
    }

    // Увеличиваем счетчик (IV)
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        if (++iv[i]) break;
    }
}

int main() {
    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Генерация ключей ECDH
    EC_KEY *key1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key1);

    EC_KEY *key2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key2);

    // Вычисление общего секрета
    const EC_GROUP *group = EC_KEY_get0_group(key1);
    int secret_len = (EC_GROUP_get_degree(group) + 7) / 8; // Размер секрета в байтах
    unsigned char *secret1 = (unsigned char *)malloc(secret_len);
    unsigned char *secret2 = (unsigned char *)malloc(secret_len);

    secret_len = ECDH_compute_key(secret1, secret_len, EC_KEY_get0_public_key(key2), key1, NULL);
    ECDH_compute_key(secret2, secret_len, EC_KEY_get0_public_key(key1), key2, NULL);

    if (memcmp(secret1, secret2, secret_len) != 0) {
        std::cerr << "Ошибка: секреты не совпадают!" << std::endl;
        return 1;
    }

    // Используем первые 32 байта общего секрета как ключ для Магмы
    unsigned char key[KEY_SIZE];
    memcpy(key, secret1, KEY_SIZE);

    // Генерация IV для режима CTR
    unsigned char iv[BLOCK_SIZE];
    if (!RAND_bytes(iv, sizeof(iv))) {
        handleErrors();
    }

    // Открываем бинарный файл для чтения
    std::ifstream file("data.bin", std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return 1;
    }

    // Открываем файл для записи зашифрованных данных
    std::ofstream outFile("output.bin", std::ios::binary);
    if (!outFile) {
        std::cerr << "Ошибка создания выходного файла!" << std::endl;
        return 1;
    }

    // Чтение и шифрование файла по блокам
    unsigned char plaintext[BLOCK_SIZE];
    unsigned char ciphertext[BLOCK_SIZE];
    int blockCount = 0;
    auto startTotal = std::chrono::high_resolution_clock::now();

    while (file.read(reinterpret_cast<char*>(plaintext), BLOCK_SIZE)) {
        auto startBlock = std::chrono::high_resolution_clock::now();

        encryptBlockCTR(plaintext, ciphertext, key, iv);

        auto endBlock = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsedBlock = endBlock - startBlock;
        std::cout << "Время шифрования блока " << blockCount << ": " << elapsedBlock.count() << " секунд" << std::endl;

        outFile.write(reinterpret_cast<char*>(ciphertext), BLOCK_SIZE);
        blockCount++;
    }

    auto endTotal = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsedTotal = endTotal - startTotal;
    std::cout << "Общее время шифрования: " << elapsedTotal.count() << " секунд" << std::endl;
    std::cout << "Количество блоков: " << blockCount << std::endl;

    // Очистка
    file.close();
    outFile.close();
    EC_KEY_free(key1);
    EC_KEY_free(key2);
    free(secret1);
    free(secret2);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}