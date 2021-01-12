#ifndef HASHER_HPP_INCLUDED_
#define HASHER_HPP_INCLUDED_

#include <algorithm>
// only need libcrypto, not libssl!
#include <openssl/evp.h>

/*******************************************************************************
Note about CRC32 code:
This implementation is based on the algorithm from Annex D of the Portable
Network Graphics (PNG) Specification (Second Edition)
<https://www.w3.org/TR/PNG>
*******************************************************************************/

namespace mji::xmph {

constexpr std::size_t hash_max_custom_digest_size = 4;  // CRC32
constexpr auto hash_max_digest_size = std::max<std::size_t>(
    EVP_MAX_MD_SIZE,
    hash_max_custom_digest_size
);

bool initHashSubsystem() {
    // libcrypto does not require explicit initialization.
    // We do not require explicit initialization (yet).
    return true;
}

struct HashDigest {
    std::size_t length;
    std::uint8_t data[hash_max_digest_size];
};

class Hasher {
private:
    bool is_finalized;

    virtual bool consume_impl(const void* data, std::size_t count) = 0;
    virtual bool finalize_impl(HashDigest* digest) = 0;

public:
    Hasher()
    : is_finalized(false)
    {}

    bool consume(const void* data, std::size_t count) {
        if (!is_finalized && data != nullptr) {
            this->consume_impl(data, count);
        } else {
            return false;
        }
    }

    bool finalize(HashDigest* digest) {
        if (!is_finalized && digest != nullptr) {
            return this->finalize_impl(digest);
        } else {
            return false;
        }
    }

    virtual ~Hasher() {
        HashDigest digest;
        this->finalize(&digest);
    }
};

/// Lookup table to speed up CRC32
class Crc32Lut {
public:
    constexpr static std::size_t length = 256;

    constexpr Crc32Lut()
    : data()
    {
        constexpr std::uint32_t poly = 0xedb88320u;
        for (std::uint32_t i = 0; i < length; i++) {
            uint32_t pre = i;
            for (int j = 0; j < 8; j++) {
                if (pre & 1) {
                    pre = poly ^ (pre >> 1);
                } else {
                    pre >>= 1;
                }
            }
            data[i] = pre;
        }
    }

    constexpr std::uint32_t operator[](size_t idx) const {
        return data[idx];
    }

private:
    std::uint32_t data[length];
};

inline constexpr Crc32Lut crc32Lut{};

class Crc32Hasher : public Hasher {
private:
    static constexpr std::uint32_t base = 0xffffffffu;

    std::uint32_t partial;

    virtual bool consume_impl(const void* data, std::size_t count) {
        uint32_t partial_next = partial;
        for (std::size_t i = 0; i < count; i++) {
            partial_next = crc32Lut[(partial_next ^ ((unsigned char*)data)[i]) & 0xff] ^ (partial_next >> 8);
        }
        partial = partial_next;
        return true;
    }

    virtual bool finalize_impl(HashDigest* digest) {
        std::uint32_t final = partial ^ base;

        // write big-endian into buffer
        digest->length = 4;
        digest->data[0] = (final >> 24) & 0xf;
        digest->data[1] = (final >> 16) & 0xf;
        digest->data[2] = (final >> 8) & 0xf;
        digest->data[3] = final & 0xf;

        return true;
    }

public:
    Crc32Hasher()
    : Hasher(),
      partial(base)
    {}

    virtual ~Crc32Hasher()
    {}
};

}

#endif  // HASHER_HPP_INCLUDED_
