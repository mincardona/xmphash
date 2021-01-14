#ifndef HASHER_HPP_INCLUDED_
#define HASHER_HPP_INCLUDED_

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

inline bool initHashSubsystem() {
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
    virtual std::size_t getDigestSizeImpl() const = 0;
    virtual const char* getNameImpl() const = 0;

public:
    Hasher()
    : isFinalized_(false)
    {}

    virtual ~Hasher()  = default;

    bool consume(const void* data, std::size_t count) {
        if (!isFinalized_ && data != nullptr) {
            consumeImpl(data, count);
            return true;
        } else {
            return false;
        }
    }

    bool finalize(void* buf, std::size_t count) {
        if (!isFinalized_ && buf != nullptr && count >= getDigestSize()) {
            if (finalizeImpl(buf)) {
                isFinalized_ = true;
                return true;
            }
        }
        return false;
    }

    std::size_t getDigestSize() const {
        return getDigestSizeImpl();
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
        auto ucdata = static_cast<const unsigned char*>(data);
        for (std::size_t i = 0; i < count; i++) {
            partial_next = crc32Lut[(partial_next ^ ucdata[i]) & 0xffu] ^ (partial_next >> 8);
        }
        partial_ = partial_next;
        return true;
    }

    bool finalizeImpl(void* buf) override {
        std::uint32_t final = partial_ ^ base;
        auto ucbuf = static_cast<unsigned char*>(buf);

        // write big-endian into buffer
        ucbuf[0] = (final >> 24) & 0xffu;
        ucbuf[1] = (final >> 16) & 0xffu;
        ucbuf[2] = (final >> 8) & 0xffu;
        ucbuf[3] = final & 0xffu;

        return true;
    }

    bool resetImpl() override {
        partial_ = base;
        return true;
    }

    std::size_t getDigestSizeImpl() const override {
        return 4;
    }

    const char* getNameImpl() const override {
        return "crc32";
    }
};

// RAII
class EvpMdCtxWrapper final {
public:
    EvpMdCtxWrapper()
    : context_(::EVP_MD_CTX_new())
    {}

    EvpMdCtxWrapper(const EvpMdCtxWrapper& other)
    : context_(::EVP_MD_CTX_new())
    {
        if (!::EVP_MD_CTX_copy_ex(context_, other.get())) {
            throw std::runtime_error("EVP_MD_CTX_copy_ex failed");
        }
    }

    EvpMdCtxWrapper(EvpMdCtxWrapper&& other)
    : context_(nullptr)
    {
        std::swap(this->context_, other.context_);
    }

    EvpMdCtxWrapper& operator=(const EvpMdCtxWrapper& other)
    {
        ::EVP_MD_CTX_free(this->context_);
        this->context_ = nullptr;
        if (!::EVP_MD_CTX_copy_ex(this->context_, other.get())) {
            throw std::runtime_error("EVP_MD_CTX_copy_ex failed");
        }
        return *this;
    }

    EvpMdCtxWrapper& operator=(EvpMdCtxWrapper&& other)
    {
        std::swap(this->context_, other.context_);
        return *this;
    }

    ~EvpMdCtxWrapper() {
        if (context_ != nullptr) {
            ::EVP_MD_CTX_free(context_);
        }
    }

    ::EVP_MD_CTX* get() {
        return context_;
    }

    const ::EVP_MD_CTX* get() const {
        return context_;
    }

private:
    ::EVP_MD_CTX* context_;
};

class EvpHasher final : public Hasher {
private:
    EvpMdCtxWrapper context_;
    std::string name_;
    // we don't own this, just treat it as an ID
    const ::EVP_MD* digest_type_;

    virtual bool consumeImpl(const void* data, std::size_t count) {
        return ::EVP_DigestUpdate(context_.get(), data, count);
    }

    virtual bool finalizeImpl(void* buf) {
        return ::EVP_DigestFinal_ex(context_.get(), static_cast<unsigned char*>(buf), nullptr);
    }

    virtual bool resetImpl() {
        return ::EVP_DigestInit_ex(context_.get(), digest_type_, nullptr);
    }

    virtual std::size_t getDigestSizeImpl() const {
        return ::EVP_MD_size(digest_type_);
    }

    virtual const char* getNameImpl() const {
        return name_.c_str();
    }

    void initContext() {
        digest_type_ = ::EVP_get_digestbyname(name_.c_str());
        if (digest_type_ == nullptr) {
            throw std::invalid_argument("unrecognized digest name: \"" + name_ + "\"");
        }

        if (!::EVP_DigestInit_ex(context_.get(), digest_type_, nullptr)) {
            throw std::runtime_error("unable to initialize digest context (EVP_DigestInit_ex failed)");
        }

        // set EVP_MD_CTX_FLAG_FINALISE? ...probably not just to be safe
        //void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
    }

public:
    EvpHasher(const char* name)
    : context_(),
      name_(name),
      digest_type_(nullptr)
    {
        initContext();
    }

    EvpHasher(std::string&& name)
    : context_(),
      name_(std::move(name)),
      digest_type_(nullptr)
    {
        initContext();
    }

    EvpHasher(const EvpHasher& other) = default;
    EvpHasher(EvpHasher&& other) = default;
    EvpHasher& operator=(const EvpHasher& other) = default;
    EvpHasher& operator=(EvpHasher&& other) = default;

    virtual ~EvpHasher() = default;
};

}

#endif  // HASHER_HPP_INCLUDED_
