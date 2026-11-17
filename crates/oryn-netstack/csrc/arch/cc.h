/* lwIP 平台适配：Apple 平台（iOS / macOS），小端。 */
#ifndef ORYN_LWIP_ARCH_CC_H
#define ORYN_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>

void oryn_lwip_assert(const char *msg, const char *file, int line);

#define LWIP_PLATFORM_DIAG(x) do { } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { oryn_lwip_assert((x), __FILE__, __LINE__); } while (0)
#define LWIP_RAND() ((u32_t)arc4random())
#define LWIP_NO_UNISTD_H 1

#endif /* ORYN_LWIP_ARCH_CC_H */
