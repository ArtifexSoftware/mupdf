#include <windows.h>
#include <winspool.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#define SYMBOL_DECLSPEC __declspec(dllexport)

EXTERN_C SYMBOL_DECLSPEC int __stdcall ShowPropertiesDialog(void *ctx, void *printername, bool show_win);
