#ifndef SOLARIS_EXPORT_H
#define SOLARIS_EXPORT_H

#if defined(_WIN32) && defined(SOLARIS_SHARED)
#if defined(SOLARIS_BUILDING_CORE)
#define SOLARIS_API __declspec(dllexport)
#else
#define SOLARIS_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define SOLARIS_API __attribute__((visibility("default")))
#else
#define SOLARIS_API
#endif

#endif
