#include <cstdio>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

static const char* key = "-----BEGIN RSA PRIVATE KEY-----\n"
                         "MIICXgIBAAKBgQCw9hzBX1gXkh85Qou9TO625SPxSxahi3M0q4oeSJiiTZDmrPcA\n"
                         "JJPPwzmh2ILLmOEXTaPm4YoZtLO0zEUnddW5Nly9wbjjgk5tXMM20IyeTEuhNKWH\n"
                         "4ej2Fyo8URJPixCdQy3TrNwZMdDJzI90QPc768Ne8uguccCqTxAK8ZtTRQIDAQAB\n"
                         "AoGBAIDOc7nRQ5bMlougQ4TDtdJM0a+130Aw9+dzoTJP10H0Qa+WYKeq+Cg3SwDi\n"
                         "TroRim3i5pWMv2/clx3XvdJuM+TJasbjDmNtZZioYgPsfXM0+G+viItyYGMg6ORq\n"
                         "vBJtgCN1SGCVxurpbCGyqD+rq113bDXSW/3UKblq0wWnqk8hAkEAzAXCOCrBandW\n"
                         "8qWEdlV8br4gwlLsNBlE/DltYJyTItgT1DIoWvWahkI5X8Hbyiq0DbksK9AxDoMe\n"
                         "yBF4BUaxnQJBAN4LcQiBK56wwQsxxXGfSEbg206/JX9ZRAScQbyncgH5eZFZ7YVN\n"
                         "wmj+150AEkuweUbgfQEun/X0B/P0S19uq8kCQQC0YbcI38xn7CFkoTCPSx+b7d+a\n"
                         "z6PkoB7c/Y0V6Pkxymclqj8BxLodT/nYDtbbVIwiwgAqsIRe91DExKUfzRQFAkBB\n"
                         "BUqxOdoDGzE8TPPLZOAuWTP/KDwbwZEIZJVfYA0jhOFTbej+yxlt04ph4B57aY7p\n"
                         "8VzJltSimjYl+tiDdo35AkEAq5qf0dTDi9N8qJ0SondPDS5AnG8FmILpfT8UZR6Y\n"
                         "RmHl2S1L+wDV1N0r3k7MFkK4HOIX7YpfSLQ+T6LwQZH0pQ==\n"
                         "-----END RSA PRIVATE KEY-----\n";

int main()
{
    BCRYPT_KEY_HANDLE _hAlg{};
    BCRYPT_KEY_HANDLE _hKey{};
    LPCWSTR _keyBlobType{};
    auto status = BCryptOpenAlgorithmProvider(&_hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    printf("0x%08x\n", status);
    _keyBlobType = BCRYPT_RSAFULLPRIVATE_BLOB;
    std::vector<unsigned char> key_mut(key, key + strlen(key));
    status = BCryptImportKeyPair(_hAlg, NULL, _keyBlobType, &_hKey, key_mut.data(), key_mut.size(), 0);
    printf("0x%08x\n", status);
    return 0;
}
