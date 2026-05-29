#pragma once

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C"{
    EXPORT char* Encrypt_String(const char* plain_text, const char* key);
    EXPORT char* Decrypt_String(const char* cipher_text, const char* key);

    EXPORT long Encrypt_Int(long value, const char* key);
    EXPORT long Decrypt_Int(long value, const char* key);

    EXPORT void Free_Memory(char* ptr);
}