#ifndef HASHER_HPP_INCLUDED_
#define HASHER_HPP_INCLUDED_

#include <cstddef>
#include <cstdint>
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

class Hasher {
private:
    bool isFinalized_;

    virtual bool consumeImpl(const void* data, std::size_t count) = 0;
    virtual bool finalizeImpl(void* buf) = 0;
    virtual bool resetImpl() = 0;
    virtual std::size_t digestSizeImpl() const = 0;
    virtual const char* getNameImpl() const = 0;

public:
    Hasher()
    : isFinalized_(false)
    {}

    virtual ~Hasher() {}

    bool consume(const void* data, std::size_t count) {
        if (!isFinalized_ && data != nullptr) {
            consumeImpl(data, count);
            return true;
        } else {
            return false;
        }
    }

    bool finalize(void* buf, std::size_t count) {
        if (!isFinalized_ && buf != nullptr && count >= digestSize()) {
            if (finalizeImpl(buf)) {
                isFinalized_ = true;
                return true;
            }
        }
        return false;
    }

    std::size_t digestSize() const {
        return digestSizeImpl();
    }

    // the returned pointer should not be used past the lifetime of this object
    const char* getName() const {
        return getNameImpl();
    }

    bool reset() {
        return resetImpl();
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

class Crc32Hasher final : public Hasher {
public:
    Crc32Hasher()
    : Hasher(),
      partial_(base)
    {}

    virtual ~Crc32Hasher()
    {}

private:
    static constexpr std::uint32_t base = 0xffffffffu;

    std::uint32_t partial_;

    bool consumeImpl(const void* data, std::size_t count) override {
        uint32_t partial_next = partial_;
        for (std::size_t i = 0; i < count; i++) {
            partial_next = crc32Lut[(partial_next ^ ((unsigned char*)data)[i]) & 0xff] ^ (partial_next >> 8);
        }
        partial_ = partial_next;
        return true;
    }

    bool finalizeImpl(void* buf) override {
        std::uint32_t final = partial_ ^ base;
        auto ucbuf = static_cast<unsigned char*>(buf);

        // write big-endian into buffer
        ucbuf[0] = (final >> 24) & 0xf;
        ucbuf[1] = (final >> 16) & 0xf;
        ucbuf[2] = (final >> 8) & 0xf;
        ucbuf[3] = final & 0xf;

        return true;
    }

    bool resetImpl() override {
        partial_ = base;
        return true;
    }

    std::size_t digestSizeImpl() const override {
        return 4;
    }

    const char* getNameImpl() const override {
        return "crc32";
    }
};

}

#endif  // HASHER_HPP_INCLUDED_
