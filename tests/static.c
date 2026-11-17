#include "library.h"

static int AppInit(Tcl_Interp *interp) {
    if (Tcl_Init(interp) != TCL_OK) return TCL_ERROR;
    return Thashlib_Init(interp);
}

int main(int argc, char **argv) {
    Tcl_Main(argc, argv, AppInit);
    return 0;
}
