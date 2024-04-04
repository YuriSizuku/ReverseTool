#define WINPE_SHARED
#if defined(__TINYC__) || (defined(_MSC_VER) && defined(_WIN64))
#define WINPE_NOASM
#endif
#define WINPE_IMPLEMENTATION
#include "winpe.h"