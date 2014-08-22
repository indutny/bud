#ifndef INCLUDE_BUD_COMMON_H_
#define INCLUDE_BUD_COMMON_H_

#if defined(__GNUC__) && ((__GNUC__ >= 4) || \
    (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
# ifdef BUILDING_V8_SHARED
#  define BUD_EXPORT __attribute__ ((visibility("default")))
# else
#  define BUD_EXPORT
# endif
#else
# define BUD_EXPORT
#endif

#endif  /* INCLUDE_BUD_COMMON_H_ */
