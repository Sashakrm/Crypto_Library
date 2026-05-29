#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>
#include <vector>
#include <string>

static const int KEY_SIZE = 32; //размер для AES-256 (256 бит = 32 байта)
static const int IV_SIZE = 12; //размер вектора (96 бит для GCM)
static const int TAG_SIZE = 16; //размер аутентификационной метки (128 бит)

//получение ключа шифрования из полученного пароля
static std::vector<unsigned char> Derive_Key(const char* key) {
    std::vector <unsigned char> out(KEY_SIZE);

    EVP_Digest(
        key,                    // входные данные
        strlen(key),            // длина входных данных
        out.data(),             // буфер для результата
        nullptr,                // фактическая длина результата (не нужна)
        EVP_sha256(),           // используемый алгоритм хеширования
        nullptr                 // дополнительные параметры (не используются)
    );

    return out;
}

//Шифрование полученной строки
char* Encrypt_String(const char* plain_text, const char *key) {
    //получение ключа шифрования из пароля
    auto key_bytes = Derive_Key(key);

    // Генерация случайного вектора инициализации
    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    // Создание контекста шифрования OpenSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Инициализация контекста для AES-256-GCM шифрования
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_bytes.data(), iv);

    int len;
    int plain_text_len=strlen(plain_text);

    // Буфер для зашифрованных данных
    std::vector<unsigned char> cipher_text(plain_text_len);

    // Шифрование данных
    EVP_EncryptUpdate(
        ctx,
        cipher_text.data(),      // буфер для зашифрованных данных
        &len,                   // количество записанных байт
        (unsigned char*)plain_text, // исходные данные
        plain_text_len);           // длина исходных данных

    int cipher_text_len=len;

    // Завершение шифрования
    EVP_EncryptFinal_ex(ctx, cipher_text.data() + len, &len);
    cipher_text_len+=len;

    // Получение аутентификационной метки (tag)
    unsigned char tag[TAG_SIZE];
    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_GET_TAG,   // операция получения метки
        TAG_SIZE,               // размер метки
        tag                     // буфер для метки
    );

    // Очистка контекста
    EVP_CIPHER_CTX_free(ctx);

    // Формирование результирующих данных: IV + зашифрованные данные + метка
    std::vector<unsigned char> result;
    result.insert(result.end(), iv, iv + IV_SIZE);
    result.insert(result.end(), cipher_text.begin(), cipher_text.begin() + cipher_text_len);
    result.insert(result.end(), tag, tag + TAG_SIZE);

    // Создание строки для возврата (с нулевым символом в конце)
    char* output = (char*)malloc(result.size()+1);
    memcpy(output, result.data(), result.size());
    output[result.size()] = 0;

    return output;
}

//Функция для расшифровки строки
char* Decrypt_String(const char* cipher_text, const char *key) {

    // Получение ключа шифрования из пароля
    auto key_bytes = Derive_Key(key);

    // Общая длина зашифрованных данных
    int total_len = strlen(cipher_text);

    // Представление входных данных как байтового массива
    const unsigned char* data = (const unsigned char*)cipher_text;

    // Разделение данных на составляющие
    const unsigned char* iv = data;                    // IV в начале
    const unsigned char* tag = data + total_len - TAG_SIZE; // метка в конце
    int cipher_len = total_len - IV_SIZE - TAG_SIZE;   // длина зашифрованных данных
    const unsigned char* cipher = data + IV_SIZE;      // зашифрованные данные

    // Создание контекста расшифрования
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Инициализация контекста для AES-256-GCM расшифрования
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_bytes.data(), iv);

    // Буфер для расшифрованных данных
    std::vector<unsigned char> plain_text(cipher_len);
    int len;

    // Расшифрование данных
    EVP_DecryptUpdate(
        ctx,
        plain_text.data(),       // буфер для расшифрованных данных
        &len,                   // количество записанных байт
        cipher,                 // зашифрованные данные
        cipher_len              // длина зашифрованных данных
    );

    // Установка аутентификационной метки для проверки целостности
    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_TAG,   // операция установки метки
        TAG_SIZE,               // размер метки
        (void*)tag              // метка для проверки
    );

    // Завершение расшифрования и проверка метки
    int ret = EVP_DecryptFinal_ex(ctx, plain_text.data(), &len);

    // Очистка контекста
    EVP_CIPHER_CTX_free(ctx);

    // Если проверка метки не удалась (данные повреждены или неверный ключ)
    if (ret <=0)
        return nullptr;

    // Создание строки для возврата (с нулевым символом в конце)
    char* output = (char*)malloc (cipher_len+1);
    memcpy(output, plain_text.data(), cipher_len);
    output[cipher_len] = 0;

    return output;
}

//Простая шифровка цифр
long Encrypt_Int(long value, const char* key) {

    //Получение ключа из пароля
    auto key_bytes = Derive_Key(key);

    long result = value;

    //XOR каждого байта ключа со значанием
    for (size_t i=0; i<key_bytes.size(); i++)
        result ^= key_bytes[i];

    return result;
}
//Функция расшифровки целого числа, расшировка идет индетично шифрованию
long Decrypt_Int(long value, const char* key) {
    return Encrypt_Int(value, key);
}
void Free_Memory(char* ptr) {
    free(ptr);
}
