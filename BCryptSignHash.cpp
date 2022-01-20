// x86_64-w64-mingw32-c++ BCryptSignHash.cpp -lbcrypt -std=c++17
//
// cl BCryptSignHash.cpp bcrypt.lib /std:c++17 /Fe:a.exe

#include <cstdint>
#include <cstdio>
#include <string_view>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>

static uint8_t _tmp_key[] = {
    0x52, 0x53, 0x41, 0x33, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xa9, 0xcf, 0x12, 0x23, 0x8b, 0xa9, 0xd0, 0x0f, 0x96, 0x1c, 0xed, 0x85, 0xac,
    0xd3, 0x2f, 0x7f, 0x97, 0x81, 0x3f, 0x5a, 0xc0, 0xa8, 0x25, 0x05, 0x5b, 0x28, 0x47, 0x74, 0x36, 0xdf, 0xec, 0x0a, 0x30,
    0x5a, 0x3f, 0x19, 0x31, 0x34, 0x48, 0x05, 0xbd, 0x3e, 0xa1, 0x88, 0x3f, 0x9c, 0x50, 0x8d, 0xe8, 0xc5, 0x41, 0x87, 0x22,
    0x40, 0x03, 0xfe, 0xee, 0x7a, 0x4d, 0xbc, 0xdc, 0x95, 0xfe, 0xd0, 0x51, 0x00, 0x1f, 0x5a, 0xd4, 0x26, 0x85, 0x8e, 0x87,
    0x12, 0xd0, 0xc2, 0x65, 0xf7, 0xe5, 0x77, 0x21, 0x19, 0x2c, 0x72, 0x9d, 0xf7, 0xbe, 0xe2, 0x5c, 0xbb, 0x59, 0xd6, 0x36,
    0xf5, 0xac, 0x1b, 0x96, 0xc7, 0xb0, 0xe6, 0xe1, 0x76, 0x7a, 0x48, 0x2d, 0x11, 0xa6, 0x8a, 0x34, 0x33, 0xa7, 0x08, 0x95,
    0x20, 0x3a, 0xb5, 0xdf, 0x32, 0x39, 0xe0, 0xd9, 0x97, 0x2b, 0x48, 0xb8, 0x87, 0xee, 0x75, 0xc8, 0x79, 0xc3, 0xb3, 0x49,
    0x8f, 0x40, 0x23, 0xac, 0xaa, 0x0e, 0xd2, 0xf8, 0xfd, 0x46, 0x9d, 0xfe, 0xe9, 0x07, 0xad, 0x4a, 0x89, 0xd2, 0x0f, 0xa9,
    0xd6, 0x72, 0x37, 0xfb, 0x4d, 0x73, 0xeb, 0xc2, 0x3d, 0xc4, 0x1e, 0x47, 0x62, 0x68, 0xda, 0xec, 0xa2, 0xb4, 0x57, 0x74,
    0xc9, 0x06, 0x3e, 0x93, 0x0f, 0x57, 0x53, 0x33, 0x79, 0x5b, 0xe5, 0xef, 0x63, 0xd3, 0xe2, 0x1d, 0xbc, 0x67, 0x55, 0xd8,
    0xd6, 0xf4, 0x31, 0x51, 0x96, 0x26, 0xf2, 0x58, 0xd7, 0xb8, 0x41, 0x14, 0x2a, 0xb1, 0x3b, 0x03, 0xb0, 0x21, 0x25, 0x48,
    0x42, 0x80, 0xea, 0x4e, 0x15, 0x9b, 0x3e, 0x10, 0x06, 0xf8, 0x79, 0xef, 0xb2, 0x4d, 0x76, 0x81, 0x0a, 0xdc, 0xb8, 0xf9,
    0xe7, 0x29, 0x71, 0xb5, 0x77, 0x6d, 0x09, 0x1f, 0x4f, 0x5b, 0x46, 0xdb, 0x3d, 0x9e, 0x2b, 0x05, 0x98, 0x9f, 0x63, 0x1d,
    0xbb, 0x2a, 0xa1, 0x4d, 0xfd, 0x08, 0x83, 0xbb, 0xaf, 0x0d, 0x9d, 0x93, 0x33, 0x08, 0xd7, 0x4b, 0xe3, 0x83, 0xd0, 0x3c,
    0xf5, 0x3c, 0x76, 0x4e, 0x93, 0xf4, 0xf3, 0x00, 0xf8, 0x1a, 0xb0, 0xea, 0x83, 0x44, 0x00, 0x48, 0x2d, 0x2d, 0x19, 0x36,
    0x5d, 0xf3, 0x3a, 0x8f, 0x69, 0xf0, 0x4c, 0x41, 0x73, 0x5e, 0x89, 0x83, 0x3e, 0x29, 0x93, 0x85, 0x67, 0xc5, 0xb7, 0x5a,
    0x7c, 0x74, 0x55, 0xf7, 0x89, 0x6e, 0x8d, 0xc4, 0x61, 0x00, 0x2c, 0x7e, 0x40, 0x27, 0x2b, 0x8a, 0x6c, 0x6b, 0xb1, 0x7c,
    0xab, 0x21, 0x71, 0x59, 0xe8, 0xb4, 0x4c, 0x08, 0x82, 0x3a, 0x30, 0x78, 0xe1, 0x36, 0x84, 0x61, 0x8d, 0x7e, 0x91, 0x28,
    0x14, 0xe9, 0xf4, 0xad, 0xef, 0x81, 0x70, 0x80, 0xda, 0xea, 0x7c, 0xd1, 0xa4, 0xc3, 0xf9, 0xe4, 0x02, 0x41, 0x9f, 0x0d,
    0x45, 0x63, 0xae, 0x80, 0xd5, 0xf5, 0x5b, 0x95, 0x7c, 0x81, 0xa1, 0x2a, 0xc2, 0xd4, 0x06, 0x3b, 0xef, 0x42, 0xe7, 0x2a,
    0x65, 0x13, 0x48, 0x5d, 0xed, 0xa1, 0x9a, 0xe3, 0xd7, 0xe4, 0xa8, 0xd4, 0x55, 0x11, 0x46, 0x88, 0x34, 0x97, 0xc4, 0x6c,
    0x27, 0x76, 0x0d, 0xc9, 0x0e, 0x49, 0x0b, 0x71, 0x45, 0x19, 0x8b, 0x13, 0x2d, 0xe3, 0x15, 0xa2, 0x18, 0xdd, 0xe3, 0x6e,
    0xe1, 0xcd, 0xd2, 0xf5, 0xd5, 0xd2, 0x9b, 0x13, 0xfe, 0x16, 0x85, 0x30, 0x8f, 0x9f, 0x03, 0x73, 0x8c, 0x1f, 0x08, 0xa6,
    0xf9, 0x97, 0x45, 0x73, 0xdd, 0x1d, 0x57, 0x0f, 0xc1, 0xe8, 0x99, 0x46, 0xcb, 0xc1, 0x03, 0x8d, 0x03, 0x1d, 0xa5, 0xe6,
    0x60, 0xa3, 0x36, 0x96, 0x3c, 0x8a, 0xce, 0x68, 0x16, 0x90, 0xc7, 0x20, 0xaf, 0x35, 0xaf, 0x0a, 0x16, 0x3b, 0x2e, 0x8e,
    0x32, 0x5c, 0xb2, 0x23, 0xc9, 0x4e, 0x0c, 0x99, 0x26, 0xbc, 0x51, 0x55, 0x8f, 0x4d, 0xa4, 0x8c, 0xe9, 0x58, 0x28, 0xe6,
    0x6d, 0x51, 0xd6, 0xa5, 0x75, 0x78, 0x79, 0x81, 0x98, 0xe2, 0xe0, 0x8b, 0x38, 0x79, 0xb5, 0x55, 0x85, 0xc0, 0x71, 0xc0,
    0x07, 0xfc, 0xf6, 0x76, 0xda, 0x84, 0x5b, 0x10, 0x75, 0x39, 0xf8, 0x18, 0xcf, 0x0c, 0x6f, 0x7d, 0xef, 0xc0, 0xb8, 0x47,
    0x22, 0x10, 0x5e, 0x22, 0xda, 0x25, 0xc6, 0x43, 0xc6, 0x73, 0x4a, 0x91, 0xf3, 0xbb, 0xf9, 0x47, 0xd2, 0x6c, 0x12, 0x9b,
    0xa0, 0x6d, 0x81
};
static const unsigned int _tmp_key_len = 603;
static uint8_t hash[] = { 0x4b, 0x3a, 0x74, 0x3a, 0x84, 0x95, 0xf8, 0xc5, 0x4a, 0xc6, 0x19, 0x29, 0xe5, 0xb4, 0x5a, 0x94,
                          0x49, 0xc3, 0x82, 0x73, 0x3e, 0x26, 0xf2, 0x6f, 0xaf, 0xa4, 0x40, 0xfa, 0x59, 0xc3, 0x9e, 0x2f };
static unsigned int _tmp_hash_len = 32;

constexpr static bool NT_SUCCESS(NTSTATUS status)
{
    return status >= 0;
}

static bool CngLogError(std::string_view name, NTSTATUS status)
{
    if (!NT_SUCCESS(status))
    {
        fprintf(stderr, "%s failed: 0x%08lx\n", std::string(name).c_str(), status);
        return true;
    }
    return false;
}

int main()
{
    printf("BCryptSignHash\n");
    BCRYPT_KEY_HANDLE _hKey{};
    BCRYPT_KEY_HANDLE _hAlg{};
    LPCWSTR _keyBlobType{ BCRYPT_RSAFULLPRIVATE_BLOB };
    auto status = BCryptOpenAlgorithmProvider(&_hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    CngLogError("BCryptOpenAlgorithmProvider", status);
    status = BCryptImportKeyPair(_hAlg, NULL, _keyBlobType, &_hKey, _tmp_key, static_cast<ULONG>(_tmp_key_len), 0);
    CngLogError("BCryptImportKeyPair", status);
    BCRYPT_PKCS1_PADDING_INFO paddingInfo{ BCRYPT_SHA256_ALGORITHM };
    DWORD cbSignature{};
    status = BCryptSignHash(_hKey, &paddingInfo, hash, _tmp_hash_len, NULL, 0, &cbSignature, BCRYPT_PAD_PKCS1);
    CngLogError("BCryptSignHash first", status);
    printf("cbSignature: %lu\n", cbSignature);
    if (cbSignature != 0)
    {
        auto pbSignature = new BYTE[cbSignature];
        BCryptSignHash(_hKey, &paddingInfo, hash, _tmp_hash_len, pbSignature, cbSignature, &cbSignature, BCRYPT_PAD_PKCS1);
        CngLogError("BCryptSignHash second", status);
        delete[] pbSignature;
    }
    cbSignature = 128; // We know beforehand it should be 128, do a test if it work when we provide enough data in output
    auto pbSignature = new BYTE[cbSignature];
    BCryptSignHash(_hKey, &paddingInfo, hash, _tmp_hash_len, pbSignature, cbSignature, &cbSignature, BCRYPT_PAD_PKCS1);
    CngLogError("BCryptSignHash third", status);
    delete[] pbSignature;
    status = BCryptDestroyKey(_hKey);
    CngLogError("BCryptDestroyKey", status);
    status = BCryptCloseAlgorithmProvider(_hAlg, 0);
    CngLogError("BCryptCloseAlgorithmProvider", status);
}
