// x86_64-w64-mingw32-g++ BCryptExportKey_RSA_test.cpp -lbcrypt -std=c++17
//
// cl BCryptExportKey_RSA_test.cpp bcrypt.lib /std:c++17 /Fe:a.exe

#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>
#include <wincrypt.h>

constexpr bool NT_SUCCESS(NTSTATUS status)
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

static bool test_key_export(LPCWSTR keyType)
{
    BCRYPT_KEY_HANDLE _hKey{};
    BCRYPT_KEY_HANDLE _hAlg{};
    NTSTATUS status{};
    bool error = false;

    // Get algorithm
    status = BCryptOpenAlgorithmProvider(&_hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    error |= CngLogError("BCryptOpenAlgorithmProvider", status);

    // Generate key
    status = BCryptGenerateKeyPair(_hAlg, &_hKey, 1024, 0);
    error |= CngLogError("BCryptGenerateKeyPair", status);
    status = BCryptFinalizeKeyPair(_hKey, 0);
    error |= CngLogError("BCryptFinalizeKeyPair", status);

    // Export key
    ULONG cbOutput{};
    status = BCryptExportKey(_hKey, NULL, keyType, NULL, 0, &cbOutput, 0);
    error |= CngLogError("BCryptExportKey", status);
    std::vector<uint8_t> blob(cbOutput);
    status = BCryptExportKey(_hKey, NULL, keyType, blob.data(), cbOutput, &cbOutput, 0);
    error |= CngLogError("BCryptExportKey", status);
    status = BCryptDestroyKey(_hKey);
    error |= CngLogError("BCryptDestroyKey", status);

    // Import key
    status = BCryptImportKeyPair(_hAlg, NULL, keyType, &_hKey, blob.data(), static_cast<ULONG>(blob.size()), 0);
    error |= CngLogError("BCryptImportKeyPair", status);
    status = BCryptDestroyKey(_hKey);
    error |= CngLogError("BCryptDestroyKey", status);
    return error;
}

int main()
{
    printf("BCryptExportKey_RSA\n");
    bool error = false;
    printf("RSAFULLPRIVATE_BLOB\n");
    error |= test_key_export(BCRYPT_RSAFULLPRIVATE_BLOB);
    printf("RSAPUBLIC_BLOB\n");
    error |= test_key_export(BCRYPT_RSAPUBLIC_BLOB);
    printf("BCryptExportKey_RSA done\n");
    return (int)error;
}
