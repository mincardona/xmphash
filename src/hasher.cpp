#include <xmphash/hasher.hpp>

namespace mji::xmph {

bool initHashSubsystem() {
    // libcrypto does not require explicit initialization.
    // We do not require explicit initialization (yet).
    return true;
}

Hasher::Hasher()
: isFinalized_(false)
{}

bool Hasher::consume(const void* data, std::size_t count) {
    if (!isFinalized_ && data != nullptr) {
        consumeImpl(data, count);
        return true;
    } else {
        return false;
    }
}

bool Hasher::finalize(void* buf, std::size_t count) {
    if (!isFinalized_ && buf != nullptr && count >= getDigestSize()) {
        if (finalizeImpl(buf)) {
            isFinalized_ = true;
            return true;
        }
    }
    return false;
}

std::size_t Hasher::getDigestSize() const {
    return getDigestSizeImpl();
}

const char* Hasher::getName() const {
    return getNameImpl();
}

bool Hasher::reset() {
    return resetImpl();
}

// Crc32Hasher

Crc32Hasher::Crc32Hasher()
: Hasher(),
  partial_(base)
{}

Crc32Hasher::~Crc32Hasher()
{}

bool Crc32Hasher::consumeImpl(const void* data, std::size_t count) {
    uint32_t partial_next = partial_;
    auto ucdata = static_cast<const unsigned char*>(data);
    for (std::size_t i = 0; i < count; i++) {
        partial_next = crc32Lut[(partial_next ^ ucdata[i]) & 0xffu] ^ (partial_next >> 8);
    }
    partial_ = partial_next;
    return true;
}

bool Crc32Hasher::finalizeImpl(void* buf) {
    std::uint32_t final = partial_ ^ base;
    auto ucbuf = static_cast<unsigned char*>(buf);

    // write big-endian into buffer
    ucbuf[0] = (final >> 24) & 0xffu;
    ucbuf[1] = (final >> 16) & 0xffu;
    ucbuf[2] = (final >> 8) & 0xffu;
    ucbuf[3] = final & 0xffu;

    return true;
}

bool Crc32Hasher::resetImpl() {
    partial_ = base;
    return true;
}

std::size_t Crc32Hasher::getDigestSizeImpl() const {
    return 4;
}

const char* Crc32Hasher::getNameImpl() const {
    return "crc32";
}

EvpMdCtxWrapper::EvpMdCtxWrapper()
: context_(::EVP_MD_CTX_new())
{}

EvpMdCtxWrapper::EvpMdCtxWrapper(const EvpMdCtxWrapper& other)
: context_(::EVP_MD_CTX_new())
{
    if (!::EVP_MD_CTX_copy_ex(context_, other.get())) {
        throw std::runtime_error("EVP_MD_CTX_copy_ex failed");
    }
}

EvpMdCtxWrapper::EvpMdCtxWrapper(EvpMdCtxWrapper&& other)
: context_(nullptr)
{
    std::swap(this->context_, other.context_);
}

EvpMdCtxWrapper& EvpMdCtxWrapper::operator=(const EvpMdCtxWrapper& other) {
    ::EVP_MD_CTX_free(this->context_);
    this->context_ = nullptr;
    if (!::EVP_MD_CTX_copy_ex(this->context_, other.get())) {
        throw std::runtime_error("EVP_MD_CTX_copy_ex failed");
    }
    return *this;
}

EvpMdCtxWrapper& EvpMdCtxWrapper::operator=(EvpMdCtxWrapper&& other) {
    std::swap(this->context_, other.context_);
    return *this;
}

EvpMdCtxWrapper::~EvpMdCtxWrapper() {
    if (context_ != nullptr) {
        ::EVP_MD_CTX_free(context_);
    }
}

::EVP_MD_CTX* EvpMdCtxWrapper::get() {
    return context_;
}

const ::EVP_MD_CTX* EvpMdCtxWrapper:: get() const {
    return context_;
}

bool EvpHasher::consumeImpl(const void* data, std::size_t count) {
    return ::EVP_DigestUpdate(context_.get(), data, count);
}

bool EvpHasher::finalizeImpl(void* buf) {
    return ::EVP_DigestFinal_ex(context_.get(), static_cast<unsigned char*>(buf), nullptr);
}

bool EvpHasher::resetImpl() {
    return ::EVP_DigestInit_ex(context_.get(), digest_type_, nullptr);
}

std::size_t EvpHasher::getDigestSizeImpl() const {
    return ::EVP_MD_size(digest_type_);
}

const char* EvpHasher::getNameImpl() const {
    return name_.c_str();
}

void EvpHasher::initContext() {
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

EvpHasher::EvpHasher(const char* name)
: context_(),
  name_(name),
  digest_type_(nullptr)
{
    initContext();
}

EvpHasher::EvpHasher(std::string&& name)
: context_(),
  name_(std::move(name)),
  digest_type_(nullptr)
{
    initContext();
}

}
