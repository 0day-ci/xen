#ifndef __X86_STRING_H__
#define __X86_STRING_H__

#define __HAVE_ARCH_MEMCPY
#define memcpy(d, s, n)       __builtin_memcpy(d, s, n)

#define __HAVE_ARCH_MEMMOVE
#define memmove(d, s, n)      __builtin_memmove(d, s, n)

#define __HAVE_ARCH_MEMSET
#define memset(s, c, n)       __builtin_memset(s, c, n)

#define strcmp(s1, s2)        __builtin_strcmp(s1, s2)
#define strncmp(s1, s2, n)    __builtin_strncmp(s1, s2, n)
#define strcasecmp(s1, s2)    __builtin_strcasecmp(s1, s2)
#define strchr(s1, c)         __builtin_strchr(s1, c)
#define strrchr(s1, c)        __builtin_strrchr(s1, c)
#define strstr(s1, s2)        __builtin_strstr(s1, s2)
#define strlen(s1)            __builtin_strlen(s1)

#endif /* __X86_STRING_H__ */
