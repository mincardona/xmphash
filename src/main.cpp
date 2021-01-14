#include <cstdio>
#include <thread>

#include <xmphash/hasher.hpp>
#include <xmphash/xplat.hpp>

#define DIE(S) do { std::perror(S); exit(-1); } while (false);

unsigned int hardware_thread_count() {
    // clamp to minimum of 1
    return std::max<unsigned int>(std::thread::hardware_concurrency(), 1);
}

int main(int argc, char** argv) {
    std::printf("Detected %u hardware threads\n", hardware_thread_count());

    if (mji::xplat::reopenStdinAsBinary()) {
        std::printf("Reopened stdin in binary mode\n");
    } else {
        std::printf("Failed to reopen stdin in binary mode\n");
    }

    if (argc < 2) {
        return 0;
    }

    mji::xmph::initHashSubsystem();

    unsigned char fbuf[4096];
    unsigned char sha256Digest[mji::xmph::hash_max_digest_size];
    unsigned char crc32Digest[mji::xmph::hash_max_digest_size];
    mji::xmph::EvpHasher sha256Hasher("sha256");
    mji::xmph::Crc32Hasher crc32Hasher;

    std::FILE* fobj = std::fopen(argv[1], "rb");
    if (fobj == nullptr) {
        DIE("failed to open file");
    }

    for (;;) {
        std::size_t bytes_read = std::fread(fbuf, 1, sizeof(fbuf), fobj);
        if (bytes_read == 0) {
            if (std::feof(fobj)) {
                fclose(fobj);
                break;
            } else {  // error
                fclose(fobj);
                DIE("failed data read from file");
            }
        }

        if (!sha256Hasher.consume(fbuf, bytes_read)) {
            fclose(fobj);
            DIE("sha256Hasher consume failed");
        }
        if (!crc32Hasher.consume(fbuf, bytes_read)) {
            fclose(fobj);
            DIE("crc32Hasher consume failed");
        }
    }
    fobj = nullptr;

    if (!sha256Hasher.finalize(sha256Digest, sizeof(sha256Digest))) {
        DIE("sha256Hasher finalize failed");
    }
    if (!crc32Hasher.finalize(crc32Digest, sizeof(crc32Digest))) {
        DIE("crc32Hasher finalize failed");
    }

    printf("%s: digest size is %zu\n", sha256Hasher.getName(), sha256Hasher.getDigestSize());
    for (std::size_t i = 0; i < sha256Hasher.getDigestSize(); i++) {
        printf("%.2hhx", sha256Digest[i]);
    }
    printf("\n");
    
    printf("%s: digest size is %zu\n", crc32Hasher.getName(), crc32Hasher.getDigestSize());
    for (std::size_t i = 0; i < crc32Hasher.getDigestSize(); i++) {
        printf("%.2hhx", crc32Digest[i]);
    }
    printf("\n");

    return 0;
}
