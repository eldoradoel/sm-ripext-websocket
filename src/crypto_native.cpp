#include "extension.h"
#include <boost/crc.hpp>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <fstream>
#include <sstream>

static cell_t CryptoMd5(IPluginContext *pContext, const cell_t *params)
{
    char *buffer;
    pContext->LocalToString(params[2], &buffer);

    unsigned char md[MD5_DIGEST_LENGTH];
    unsigned char ctxresult[MD5_DIGEST_LENGTH * 2 + 1];

    MD5_CTX ctx;

    if (!MD5_Init(&ctx))
    {
        pContext->ThrowNativeError("MD5_Init failed");
        return 0;
    }

    if (!MD5_Update(&ctx, buffer, std::strlen(buffer)))
    {
        pContext->ThrowNativeError("MD5_Update failed");
        return 0;
    }

    if (!MD5_Final(md, &ctx))
    {
        pContext->ThrowNativeError("MD5_Final failed");
        return 0;
    }

    memset(ctxresult, 0, MD5_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        if (params[5])
        {
            std::sprintf((char *)&ctxresult[i * 2], "%02X", md[i]);
        }
        else
        {
            std::sprintf((char *)&ctxresult[i * 2], "%02x", md[i]);
        }
    }
    pContext->StringToLocalUTF8(params[3], params[4], (char *)ctxresult, nullptr);

    return 1;
}

static cell_t CryptoMd5File(IPluginContext *pContext, const cell_t *params)
{
    char *path;
    pContext->LocalToString(params[2], &path);

    char realpath[PLATFORM_MAX_PATH];
    smutils->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", path);

    unsigned char md[MD5_DIGEST_LENGTH];
    unsigned char ctxresult[MD5_DIGEST_LENGTH * 2 + 1];
    char fsbuf[4096];

    MD5_CTX ctx;

    if (!MD5_Init(&ctx))
    {
        pContext->ThrowNativeError("MD5_Init failed");
        return 0;
    }

    std::ifstream fs(realpath, std::ios::in | std::ios::binary);

    if (!fs.is_open())
    {
        pContext->ThrowNativeError("Could not open file for MD5 calculation: %s", realpath);
        return 0;
    }

    do
    {
        fs.read(fsbuf, sizeof(fsbuf));
        if (!MD5_Update(&ctx, fsbuf, fs.gcount()))
        {
            fs.close();
            pContext->ThrowNativeError("MD5_Update failed");
            return 0;
        }
    } while (fs);

    if (fs.eof())
    {
        fs.close();
        if (!MD5_Final(md, &ctx))
        {
            pContext->ThrowNativeError("MD5_Final failed");
            return 0;
        }
        else
        {
            memset(ctxresult, 0, MD5_DIGEST_LENGTH * 2 + 1);
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
            {
                if (params[5])
                {
                    std::sprintf((char *)&ctxresult[i * 2], "%02X", md[i]);
                }
                else
                {
                    std::sprintf((char *)&ctxresult[i * 2], "%02x", md[i]);
                }
            }
            pContext->StringToLocalUTF8(params[3], params[4], (char *)ctxresult, nullptr);
            return 1;
        }
    }
    else
    {
        fs.close();
        pContext->ThrowNativeError("File read failed %s", realpath);
        return 0;
    }
}

static cell_t CryptoSHA1(IPluginContext *pContext, const cell_t *params)
{
    char *buffer;
    pContext->LocalToString(params[2], &buffer);

    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned char ctxresult[SHA_DIGEST_LENGTH * 2 + 1];

    SHA_CTX ctx;

    if (!SHA1_Init(&ctx))
    {
        pContext->ThrowNativeError("SHA1_Init failed");
        return 0;
    }

    if (!SHA1_Update(&ctx, buffer, std::strlen(buffer)))
    {
        pContext->ThrowNativeError("SHA1_Update failed");
        return 0;
    }

    if (!SHA1_Final(md, &ctx))
    {
        pContext->ThrowNativeError("SHA1_Final failed");
        return 0;
    }

    memset(ctxresult, 0, SHA_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        if (params[5])
        {
            std::sprintf((char *)&ctxresult[i * 2], "%02X", md[i]);
        }
        else
        {
            std::sprintf((char *)&ctxresult[i * 2], "%02x", md[i]);
        }
    }
    pContext->StringToLocalUTF8(params[3], params[4], (char *)ctxresult, nullptr);

    return 1;
}

static cell_t CryptoSHA1File(IPluginContext *pContext, const cell_t *params)
{
    char *path;
    pContext->LocalToString(params[2], &path);

    char realpath[PLATFORM_MAX_PATH];
    smutils->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", path);

    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned char ctxresult[SHA_DIGEST_LENGTH * 2 + 1];
    char fsbuf[4096];

    SHA_CTX ctx;

    if (!SHA1_Init(&ctx))
    {
        pContext->ThrowNativeError("SHA1_Init failed");
        return 0;
    }

    std::ifstream fs(realpath, std::ios::in | std::ios::binary);

    if (!fs.is_open())
    {
        pContext->ThrowNativeError("Could not open file for SHA1 calculation: %s", realpath);
        return 0;
    }

    do
    {
        fs.read(fsbuf, sizeof(fsbuf));
        if (!SHA1_Update(&ctx, fsbuf, fs.gcount()))
        {
            fs.close();
            pContext->ThrowNativeError("SHA1_Update failed");
            return 0;
        }
    } while (fs);

    if (fs.eof())
    {
        fs.close();
        if (!SHA1_Final(md, &ctx))
        {
            pContext->ThrowNativeError("SHA1_Final failed");
            return 0;
        }
        else
        {
            memset(ctxresult, 0, SHA_DIGEST_LENGTH * 2 + 1);
            for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
            {
                if (params[5])
                {
                    std::sprintf((char *)&ctxresult[i * 2], "%02X", md[i]);
                }
                else
                {
                    std::sprintf((char *)&ctxresult[i * 2], "%02x", md[i]);
                }
            }
            pContext->StringToLocalUTF8(params[3], params[4], (char *)ctxresult, nullptr);
            return 1;
        }
    }
    else
    {
        fs.close();
        pContext->ThrowNativeError("File read failed %s", realpath);
        return 0;
    }
}

static cell_t CryptoSHA256(IPluginContext *pContext, const cell_t *params)
{
    char *buffer;
    pContext->LocalToString(params[2], &buffer);

    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned char ctxresult[SHA256_DIGEST_LENGTH * 2 + 1];

    SHA256_CTX ctx;

    if (!SHA256_Init(&ctx))
    {
        pContext->ThrowNativeError("SHA256_Init failed");
        return 0;
    }

    if (!SHA256_Update(&ctx, buffer, std::strlen(buffer)))
    {
        pContext->ThrowNativeError("SHA256_Update failed");
        return 0;
    }

    if (!SHA256_Final(md, &ctx))
    {
        pContext->ThrowNativeError("SHA256_Final failed");
        return 0;
    }

    memset(ctxresult, 0, SHA256_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        if (params[5])
        {
            std::sprintf((char *)&ctxresult[i * 2], "%02X", md[i]);
        }
        else
        {
            std::sprintf((char *)&ctxresult[i * 2], "%02x", md[i]);
        }
    }
    pContext->StringToLocalUTF8(params[3], params[4], (char *)ctxresult, nullptr);

    return 1;
}

static cell_t CryptoSHA256File(IPluginContext *pContext, const cell_t *params)
{
    char *path;
    pContext->LocalToString(params[2], &path);

    char realpath[PLATFORM_MAX_PATH];
    smutils->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", path);

    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned char ctxresult[SHA256_DIGEST_LENGTH * 2 + 1];
    char fsbuf[4096];

    SHA256_CTX ctx;

    if (!SHA256_Init(&ctx))
    {
        pContext->ThrowNativeError("SHA256_Init failed");
        return 0;
    }

    std::ifstream fs(realpath, std::ios::in | std::ios::binary);

    if (!fs.is_open())
    {
        pContext->ThrowNativeError("Could not open file for SHA256 calculation: %s", realpath);
        return 0;
    }

    do
    {
        fs.read(fsbuf, sizeof(fsbuf));
        if (!SHA256_Update(&ctx, fsbuf, fs.gcount()))
        {
            fs.close();
            pContext->ThrowNativeError("SHA256_Update failed");
            return 0;
        }
    } while (fs);

    if (fs.eof())
    {
        fs.close();
        if (!SHA256_Final(md, &ctx))
        {
            pContext->ThrowNativeError("SHA256_Final failed");
            return 0;
        }
        else
        {
            memset(ctxresult, 0, SHA256_DIGEST_LENGTH * 2 + 1);
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                if (params[5])
                {
                    std::sprintf((char *)&ctxresult[i * 2], "%02X", md[i]);
                }
                else
                {
                    std::sprintf((char *)&ctxresult[i * 2], "%02x", md[i]);
                }
            }
            pContext->StringToLocalUTF8(params[3], params[4], (char *)ctxresult, nullptr);
            return 1;
        }
    }
    else
    {
        fs.close();
        pContext->ThrowNativeError("File read failed %s", realpath);
        return 0;
    }
}

static cell_t CryptoSHA512(IPluginContext *pContext, const cell_t *params)
{
    char *buffer;
    pContext->LocalToString(params[2], &buffer);

    unsigned char md[SHA512_DIGEST_LENGTH];
    unsigned char ctxresult[SHA512_DIGEST_LENGTH * 2 + 1];

    SHA512_CTX ctx;

    if (!SHA512_Init(&ctx))
    {
        pContext->ThrowNativeError("SHA512_Init failed");
        return 0;
    }

    if (!SHA512_Update(&ctx, buffer, std::strlen(buffer)))
    {
        pContext->ThrowNativeError("SHA512_Update failed");
        return 0;
    }

    if (!SHA512_Final(md, &ctx))
    {
        pContext->ThrowNativeError("SHA512_Final failed");
        return 0;
    }

    memset(ctxresult, 0, SHA512_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
    {
        if (params[5])
        {
            std::sprintf((char *)&ctxresult[i * 2], "%02X", md[i]);
        }
        else
        {
            std::sprintf((char *)&ctxresult[i * 2], "%02x", md[i]);
        }
    }
    pContext->StringToLocalUTF8(params[3], params[4], (char *)ctxresult, nullptr);

    return 1;
}

static cell_t CryptoSHA512File(IPluginContext *pContext, const cell_t *params)
{
    char *path;
    pContext->LocalToString(params[2], &path);

    char realpath[PLATFORM_MAX_PATH];
    smutils->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", path);

    unsigned char md[SHA512_DIGEST_LENGTH];
    unsigned char ctxresult[SHA512_DIGEST_LENGTH * 2 + 1];
    char fsbuf[4096];

    SHA512_CTX ctx;

    if (!SHA512_Init(&ctx))
    {
        pContext->ThrowNativeError("SHA512_Init failed");
        return 0;
    }

    std::ifstream fs(realpath, std::ios::in | std::ios::binary);

    if (!fs.is_open())
    {
        pContext->ThrowNativeError("Could not open file for SHA512 calculation: %s", realpath);
        return 0;
    }

    do
    {
        fs.read(fsbuf, sizeof(fsbuf));
        if (!SHA512_Update(&ctx, fsbuf, fs.gcount()))
        {
            fs.close();
            pContext->ThrowNativeError("SHA512_Update failed");
            return 0;
        }
    } while (fs);

    if (fs.eof())
    {
        fs.close();
        if (!SHA512_Final(md, &ctx))
        {
            pContext->ThrowNativeError("SHA512_Final failed");
            return 0;
        }
        else
        {
            memset(ctxresult, 0, SHA512_DIGEST_LENGTH * 2 + 1);
            for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
            {
                if (params[5])
                {
                    std::sprintf((char *)&ctxresult[i * 2], "%02X", md[i]);
                }
                else
                {
                    std::sprintf((char *)&ctxresult[i * 2], "%02x", md[i]);
                }
            }
            pContext->StringToLocalUTF8(params[3], params[4], (char *)ctxresult, nullptr);
            return 1;
        }
    }
    else
    {
        fs.close();
        pContext->ThrowNativeError("File read failed %s", realpath);
        return 0;
    }
}

static cell_t CryptoCRC16(IPluginContext *pContext, const cell_t *params)
{
    char *buffer;
    pContext->LocalToString(params[2], &buffer);

    boost::crc_16_type crc;
    crc.process_bytes(buffer, std::strlen(buffer));

    char crchexbuffer[16];

    if (params[6])
    {
        if (params[5])
        {
            std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%04X", crc.checksum());
        }
        else
        {
            std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%04x", crc.checksum());
        }
        pContext->StringToLocalUTF8(params[3], params[4], crchexbuffer, nullptr);
        return 1;
    }
    else
    {
        std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%d", crc.checksum());
        pContext->StringToLocalUTF8(params[3], params[4], crchexbuffer, nullptr);
        return 1;
    }
}

static cell_t CryptoCRC16File(IPluginContext *pContext, const cell_t *params)
{
    char *path;
    pContext->LocalToString(params[2], &path);

    char realpath[PLATFORM_MAX_PATH];
    smutils->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", path);

    boost::crc_16_type crc;
    char fsbuf[4096];

    std::ifstream fs(realpath, std::ios::in | std::ios::binary);

    if (!fs.is_open())
    {
        pContext->ThrowNativeError("Could not open file for CRC calculation: %s", realpath);
        return 0;
    }

    do
    {
        fs.read(fsbuf, sizeof(fsbuf));
        crc.process_bytes(fsbuf, fs.gcount());
    } while (fs);

    if (fs.eof())
    {
        fs.close();
        char crchexbuffer[16];
        if (params[6])
        {
            if (params[5])
            {
                std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%04X", crc.checksum());
            }
            else
            {
                std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%04x", crc.checksum());
            }
            pContext->StringToLocalUTF8(params[3], params[4], crchexbuffer, nullptr);
        }
        else
        {
            std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%d", crc.checksum());
            pContext->StringToLocalUTF8(params[3], params[4], crchexbuffer, nullptr);
        }
        return 1;
    }
    else
    {
        fs.close();
        pContext->ThrowNativeError("File read failed %s", realpath);
        return 0;
    }
}

static cell_t CryptoCRC32(IPluginContext *pContext, const cell_t *params)
{
    char *buffer;
    pContext->LocalToString(params[2], &buffer);

    boost::crc_32_type crc;
    crc.process_bytes(buffer, std::strlen(buffer));

    char crchexbuffer[16];

    if (params[6])
    {
        if (params[5])
        {
            std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%08X", crc.checksum());
        }
        else
        {
            std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%08x", crc.checksum());
        }
        pContext->StringToLocalUTF8(params[3], params[4], crchexbuffer, nullptr);
        return 1;
    }
    else
    {
        std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%d", crc.checksum());
        pContext->StringToLocalUTF8(params[3], params[4], crchexbuffer, nullptr);
        return 1;
    }
}

static cell_t CryptoCRC32File(IPluginContext *pContext, const cell_t *params)
{
    char *path;
    pContext->LocalToString(params[2], &path);

    char realpath[PLATFORM_MAX_PATH];
    smutils->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", path);

    boost::crc_32_type crc;
    char fsbuf[4096];

    std::ifstream fs(realpath, std::ios::in | std::ios::binary);

    if (!fs.is_open())
    {
        pContext->ThrowNativeError("Could not open file for CRC calculation: %s", realpath);
        return 0;
    }

    do
    {
        fs.read(fsbuf, sizeof(fsbuf));
        crc.process_bytes(fsbuf, fs.gcount());
    } while (fs);

    if (fs.eof())
    {
        fs.close();
        char crchexbuffer[16];
        if (params[6])
        {
            if (params[5])
            {
                std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%08X", crc.checksum());
            }
            else
            {
                std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%08x", crc.checksum());
            }
            pContext->StringToLocalUTF8(params[3], params[4], crchexbuffer, nullptr);
        }
        else
        {
            std::snprintf(crchexbuffer, sizeof(crchexbuffer), "%d", crc.checksum());
            pContext->StringToLocalUTF8(params[3], params[4], crchexbuffer, nullptr);
        }
        return 1;
    }
    else
    {
        fs.close();
        pContext->ThrowNativeError("File read failed %s", realpath);
        return 0;
    }
}

const sp_nativeinfo_t crypto_native[] = {
    {"Crypto.MD5", CryptoMd5},
    {"Crypto.MD5File", CryptoMd5File},
    {"Crypto.SHA1", CryptoSHA1},
    {"Crypto.SHA1File", CryptoSHA1File},
    {"Crypto.SHA256", CryptoSHA256},
    {"Crypto.SHA256File", CryptoSHA256File},
    {"Crypto.SHA512", CryptoSHA512},
    {"Crypto.SHA512File", CryptoSHA512File},
    {"Crypto.CRC16", CryptoCRC16},
    {"Crypto.CRC16File", CryptoCRC16File},
    {"Crypto.CRC32", CryptoCRC32},
    {"Crypto.CRC32File", CryptoCRC32File},
    {nullptr, nullptr}};