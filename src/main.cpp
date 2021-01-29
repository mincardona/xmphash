#include <cassert>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <getopt.h>

#include <xmphash/hasher.hpp>
#include <xmphash/xplat.hpp>

namespace xmph = mji::xmph;

#define DIE(S) do { std::fprintf(stderr, S); exit(-1); } while (false);

unsigned int hardware_thread_count() {
    // clamp to minimum of 1
    return std::max<unsigned int>(std::thread::hardware_concurrency(), 1);
}

namespace karg {

enum Arg : int {
    // single-char compatible
    CHECK_INTEGRITY = 'i',
    USE_BINARY_MODE = 'b',
    USE_TEXT_MODE = 't',
    USE_ZERO_TERMINATE = 'z',
    CONTINUE = 'c',

    // long only
    HELP = 1001
};

constexpr char optShortStr[] = "ibtzc";

}  // namespace karg


struct ProcFlags {
public:
    bool checkIntegrity = false;
    bool binaryMode = true;
    bool zeroTerminate = false;
    bool help = false;
    bool doContinue = false;
};

// note: returned pos args excludes program name
std::optional<std::pair<ProcFlags, std::vector<std::string>>>
parseCliArgs(int argc, char** argv) {
    ProcFlags procFlags;
    bool fileReadModeSet = false;
    ::option longOpts[] = {
        {"check-integrity", no_argument, nullptr, karg::CHECK_INTEGRITY},
        {"binary", no_argument, nullptr, karg::USE_BINARY_MODE},
        {"text", no_argument, nullptr, karg::USE_TEXT_MODE},
        {"zero", no_argument, nullptr, karg::USE_ZERO_TERMINATE},
        {"continue", no_argument, nullptr, karg::CONTINUE},

        {"help", no_argument, nullptr, karg::HELP},
        {nullptr, 0, nullptr, 0}
    };
    int optionIdx = 0;
    // enable automatically printing error messages for unknown options or
    // missing required arguments
    ::opterr = 1;

    for (;;) {
        // Arguments to short and long options will be stored in ::optarg
        // (char*)
        // Unknown option characters, or characters with missing arguments, will
        // be stored in ::optopt (int)
        // The optionIdx variable contains the index of the detected long option
        // entry in the longOpts array (so the name is easily obtained)
        int c = ::getopt_long(argc, argv, karg::optShortStr, longOpts, &optionIdx);

        if (c == -1) {
            // no more options
            break;
        } else if (c == '?' || c == ':') {
            // unknown option char or option char with missing argument, stored
            // in ::optopt (char*)
            // TODO: handle this
            std::fprintf(stderr, "getopt_long returned %d\n", c);
            return {};
        }

        // TODO: what happens if a long option is missing a required argument?
        // Does getopt_long just set ::optarg to null and expect that you check
        // whether the argument should have been supplied using optionIdx?
        // Also check returning ':' on missing arguments if ':' is the first
        // character in the short string.
        // Assuming for now that it just returns '?' or ':'.
        switch (c) {
        case karg::CHECK_INTEGRITY:
            procFlags.checkIntegrity = true;
            break;
        case karg::USE_BINARY_MODE:
            if (fileReadModeSet) {
                std::fprintf(stderr, "File read mode set twice\n");
                return {};
            }
            fileReadModeSet = true;
            procFlags.binaryMode = true;
            break;
        case karg::USE_TEXT_MODE:
            if (fileReadModeSet) {
                fprintf(stderr, "File read mode set twice\n");
                return {};
            }
            fileReadModeSet = true;
            procFlags.binaryMode = false;
            break;
        case karg::USE_ZERO_TERMINATE:
            procFlags.zeroTerminate = true;
            break;
        case karg::CONTINUE:
            procFlags.doContinue = true;
            break;
        case karg::HELP:
            procFlags.help = true;
            break;
        case 0:
            // a long option requested that a value be stored instead of
            // returned. We don't specify any such options
            assert(false);
            continue;
        default:
            std::fprintf(stderr, "Unexpected getopt_long return value %d\n", c);
            return {};
        }
    }

    return std::optional<std::pair<ProcFlags, std::vector<std::string>>>(
        std::in_place,
        std::move(procFlags),
        std::vector<std::string>(argv + ::optind, argv + argc)
    );
}

void printHelp() {
    std::printf("[insert help]\n");
}

class CFileWrapper final {
public:
    std::FILE* fp;

    CFileWrapper(std::FILE* fp)
    : fp(fp)
    {}

    CFileWrapper(const CFileWrapper&) = delete;
    CFileWrapper& operator=(const CFileWrapper&) = delete;

    CFileWrapper(CFileWrapper&& other)
    : fp(other.fp)
    {
        other.fp = nullptr;
    }

    CFileWrapper& operator=(CFileWrapper&& other)
    {
        fp = other.fp;
        other.fp = nullptr;
        return *this;
    }

    int close() {
        if (fp != nullptr) {
            int ret = std::fclose(fp);
            fp = nullptr;
            return ret;
        } else {
            return EOF;
        }
    }

    ~CFileWrapper() {
        close();
    }
};

int main(int argc, char** argv) {
    std::printf("Detected %u hardware threads\n", hardware_thread_count());

    std::optional<std::pair<ProcFlags, std::vector<std::string>>> cliArgs =
        parseCliArgs(argc, argv);

    if (!cliArgs) {
        std::fprintf(stderr, "Error processing command arguments\n");
        return -1;
    }

    ProcFlags& procFlags = cliArgs->first;
    std::vector<std::string>& posArgs = cliArgs->second;

    if (procFlags.help) {
        printHelp();
        return 0;
    } else if (posArgs.size() != 2) {
        std::fprintf(stderr, "Wrong number of positional arguments - expected 2\n");
        return -1;
    }

    std::vector<std::string> algoEls = xmph::splitOnChar(posArgs[0].data(), ',');
    assert(algoEls.size() > 0);

    if (procFlags.checkIntegrity) {
        assert("not implemented");
    } else {
        // compute hashes of multiple files

        // for algo in algoEls, construct a hasher
        std::vector<std::unique_ptr<xmph::Hasher>> hashers;
        // TODO: should duplicate hash names be an error?
        for (const auto& algoName : algoEls) {
            if (algoName == "crc32") {
                hashers.push_back(std::make_unique<xmph::Crc32Hasher>());
            } else {
                // TODO: could throw!
                hashers.push_back(std::make_unique<xmph::EvpHasher>(algoName.c_str()));
            }
        }

        // open file
        const std::string& inFileName = posArgs[1];
        std::FILE* inFilePtr = nullptr;
        errno = 0;
        if (inFileName == "-") {
            // stdin
            if (procFlags.binaryMode && !mji::xplat::reopenStdinAsBinary()) {
                std::fprintf(stderr, "Failed to reopen stdin as binary");
                return -1;
            }
            inFilePtr = stdin;
        } else {
            const char* openMode;
            if (procFlags.binaryMode) {
                openMode = "rb";
            } else {
                openMode = "r";
            }
            inFilePtr = std::fopen(inFileName.c_str(), openMode);
        }

        if (!inFilePtr) {
            std::fprintf(stderr, "Unable to open file: %s", std::strerror(errno));
            return -1;
        }

        CFileWrapper inFile{inFilePtr};

        // send file data through hashers
        constexpr std::size_t inBufSize = 4096;
        auto inBuf = std::make_unique<unsigned char[]>(inBufSize);
        // this is the critical loop
        for (;;) {
            std::size_t bytesRead = std::fread(inBuf.get(), 1, inBufSize, inFile.fp);
            if (bytesRead == 0) {
                if (std::feof(inFile.fp)) {
                    break;
                } else {
                    std::fprintf(stderr, "Failed while reading data from file\n");
                    return -1;
                }
            }
            for (auto& hasher : hashers) {
                if (!hasher->consume(inBuf.get(), bytesRead)) {
                    std::fprintf(stderr, "Hasher \"%s\" failed to consume data\n", hasher->getName());
                    return -1;
                }
            }
        }

        // close file
        inFile.close();

        std::vector<std::unique_ptr<unsigned char[]>> digests;
        // finalize hashers
        for (auto& hasher : hashers) {
            digests.push_back(std::make_unique<unsigned char[]>(xmph::hash_max_digest_size));
            if (!hasher->finalize(digests.back().get(), xmph::hash_max_digest_size)) {
                std::fprintf(stderr, "Failed to finalize hasher \"%s\"\n", hasher->getName());
                return -1;
            }
        }
        // print results

        for (std::size_t i = 0; i < hashers.size(); i++) {
            std::printf("%s: %s\n",
                hashers[i]->getName(),
                xmph::bytesToStr(digests[i].get(), hashers[i]->getDigestSize()).c_str()
            );
        }
    }

    return 0;
}
