#include <xmphash/xplat.hpp>

#ifdef _WIN32
///////////////////////////////////////////////////////////////////////////////
// Windows
///////////////////////////////////////////////////////////////////////////////

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <stdio.h>

#include <fcntl.h>
#include <io.h>

namespace mji::xplat {

bool reopenStdinAsBinary()
{
    int fno = _fileno(stdin);
    if (fno == -1) {
        return false;
    }

    return _setmode(fno, _O_BINARY) != -1;
}

}

#else
///////////////////////////////////////////////////////////////////////////////
// Linux
///////////////////////////////////////////////////////////////////////////////

#include <cstdio>

namespace mji::xplat {

bool reopenStdinAsBinary()
{
    return std::freopen(nullptr, "rb", stdin) != nullptr;
}

}

#endif
