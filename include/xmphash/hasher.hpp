#ifndef MJI_HASHER_HPP_INCLUDED_
#define MJI_HASHER_HPP_INCLUDED_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
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

bool initHashSubsystem();

class Hasher {
public:
    Hasher();
    virtual ~Hasher() = default;

    bool consume(const void* data, std::size_t count);
    bool finalize(void* buf, std::size_t count);
    std::size_t getDigestSize() const;
    // the returned pointer should not be used past the lifetime of this object
    const char* getName() const;
    bool reset();

private:
    bool isFinalized_;

    virtual bool consumeImpl(const void* data, std::size_t count) = 0;
    virtual bool finalizeImpl(void* buf) = 0;
    virtual bool resetImpl() = 0;
    virtual std::size_t getDigestSizeImpl() const = 0;
    virtual const char* getNameImpl() const = 0;
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
    Crc32Hasher();
    ~Crc32Hasher();

    Crc32Hasher(const Crc32Hasher& other) = default;
    Crc32Hasher(Crc32Hasher&& other) = default;
    Crc32Hasher& operator=(const Crc32Hasher& other) = default;
    Crc32Hasher& operator=(Crc32Hasher&& other) = default;

private:
    static constexpr std::uint32_t base = 0xffffffffu;

    std::uint32_t partial_;

    bool consumeImpl(const void* data, std::size_t count) override;
    bool finalizeImpl(void* buf) override;
    bool resetImpl() override;
    std::size_t getDigestSizeImpl() const override;
    const char* getNameImpl() const override;
};

// RAII
class EvpMdCtxWrapper final {
public:
    EvpMdCtxWrapper();
    ~EvpMdCtxWrapper();

    EvpMdCtxWrapper(const EvpMdCtxWrapper& other);
    EvpMdCtxWrapper(EvpMdCtxWrapper&& other);
    EvpMdCtxWrapper& operator=(const EvpMdCtxWrapper& other);
    EvpMdCtxWrapper& operator=(EvpMdCtxWrapper&& other);

    ::EVP_MD_CTX* get();
    const ::EVP_MD_CTX* get() const;

private:
    ::EVP_MD_CTX* context_;
};

class EvpHasher final : public Hasher {
public:
    EvpHasher(const char* name);
    EvpHasher(std::string&& name);
    ~EvpHasher() = default;

    EvpHasher(const EvpHasher& other) = default;
    EvpHasher(EvpHasher&& other) = default;
    EvpHasher& operator=(const EvpHasher& other) = default;
    EvpHasher& operator=(EvpHasher&& other) = default;

private:
    EvpMdCtxWrapper context_;
    std::string name_;
    // we don't own this, just treat it as an ID
    const ::EVP_MD* digest_type_;

    bool consumeImpl(const void* data, std::size_t count) override;
    bool finalizeImpl(void* buf) override;
    bool resetImpl() override;
    std::size_t getDigestSizeImpl() const override;
    const char* getNameImpl() const override;
    void initContext();
};

}

#endif  // MJI_HASHER_HPP_INCLUDED_
