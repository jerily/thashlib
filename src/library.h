/* Copyright (c) 2026 Neofytos Dimitriou <neo@jerily.cy>
 * SPDX-License-Identifier: MIT
 */
#ifndef THASHLIB_LIBRARY_H
#define THASHLIB_LIBRARY_H
#include <tcl.h>
#ifdef BUILD_thashlib
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif
#ifdef __cplusplus
extern "C" {
#endif
EXTERN int Thashlib_Init(Tcl_Interp *interp);
#ifdef __cplusplus
}
#endif
#endif
