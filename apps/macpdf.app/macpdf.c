#include "macpdf.h"

static void
init_window(viewctx *ctx)
{
    WindowRef window = ctx->window;
    HIViewRef viewPane;
    static const HIViewID viewPaneID = { 'Poof', 666 };
    OSStatus err;

    err = HIViewFindByID(HIViewGetRoot(window), viewPaneID, &viewPane);
    printf("err from findbyid: %d\n", err);
}

int
openpdf(WindowRef window, const char *filename)
{
    HIViewRef viewPane;
    static const HIViewID viewPaneID = { 'Poof', 666 };
    OSStatus err;

    err = HIViewFindByID(HIViewGetRoot(window), viewPaneID, &viewPane);
    require_noerr(err, cleanup);

    err = view_openpdf(viewPane, filename);
    require_noerr(err, cleanup);

    err = view_showpage(viewPane);

 cleanup:
    return err;
}

int main(int argc, char *argv[])
{
    IBNibRef nibRef;
    OSStatus err;
    WindowRef window;

    fz_cpudetect();
    fz_accelerate();

    err = view_register();
    require_noerr(err, CantRegisterView);

    err = CreateNibReference(CFSTR("main"), &nibRef);
    printf("err = %d\n", err);
    require_noerr(err, CantGetNibRef);

    err = SetMenuBarFromNib(nibRef, CFSTR("MenuBar"));
    require_noerr(err, CantSetMenuBar);
 
    err = CreateWindowFromNib(nibRef, CFSTR("MainWindow"), &window);
    require_noerr(err, CantCreateWindow);

    openpdf(window, "tiger.pdf");

    DisposeNibReference(nibRef);

    ShowWindow(window);
    RunApplicationEventLoop();

 CantGetNibRef:
 CantSetMenuBar:
 CantCreateWindow:
 CantRegisterView:

    return err;
}
