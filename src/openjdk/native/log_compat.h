#ifndef _CONSCRYPT_LOG_COMPAT_H
#define _CONSCRYPT_LOG_COMPAT_H

#include "unused.h"

#define LOG_INFO ((void)0)

#define ALOG(...) \
            VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGD(...) \
            VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGE(...) \
            VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGV(...) \
            VA_ARGS_UNUSED(__VA_ARGS__)

#endif /* _CONSCRYPT_LOG_COMPAT_H */
