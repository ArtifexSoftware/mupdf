#include <Carbon/Carbon.h>

#include <fitz.h>
#include <mupdf.h>

#define kViewClassID CFSTR("com.artofcode.mupdf.View")
#define kViewPrivate 'MU_v'

typedef struct viewctx
{
    WindowRef window;
    HIViewRef view;
    char *doctitle;
	
    float zoom;
    int rotate;
    int pageno;

    pdf_page *page;
    fz_obj *pageobj;

    pdf_xref *xref;
    pdf_pagetree *pages;
    pdf_outline *outline;
    fz_renderer *rast;
    fz_pixmap *image;
} viewctx;

static OSStatus
view_construct(EventRef inEvent)
{
    OSStatus err;
    viewctx *ctx;

    ctx = (viewctx *)malloc(sizeof(viewctx));
    require_action(ctx != NULL, CantMalloc, err = memFullErr);
    err = GetEventParameter(inEvent, kEventParamHIObjectInstance,
			    typeHIObjectRef, NULL, sizeof(HIObjectRef), NULL,
			    (HIObjectRef *)&ctx->view);
    require_noerr(err, ParameterMissing);
    err = SetEventParameter(inEvent, kEventParamHIObjectInstance,
			    typeVoidPtr, sizeof(viewctx *), &ctx);

 ParameterMissing:
    if (err != noErr)
	free(ctx);

 CantMalloc:
    return err;
}

static OSStatus
view_destruct(EventRef inEvent, viewctx *inData)
{
    free(inData);
    return noErr;
}

static OSStatus
view_initialize(EventHandlerCallRef inCallRef, EventRef inEvent,
		   viewctx *ctx)
{
    OSStatus err;
    HIRect bounds;

    err = CallNextEventHandler(inCallRef, inEvent);
    require_noerr(err, TroubleInSuperClass);

    ctx->zoom = 1.0;
    ctx->rotate = 0;
    ctx->pageno = 1;
    ctx->window = nil;

 ParameterMissing:
 TroubleInSuperClass:
    return err;
}

#ifndef M_PI
#define M_PI            3.14159265358979323846  /* pi */
#endif

static void
cgcontext_set_rgba(CGContextRef ctx, unsigned int rgba)
{
    const double norm = 1.0 / 255;
    CGContextSetRGBFillColor(ctx,
			     ((rgba >> 24) & 0xff) * norm,
			     ((rgba >> 16) & 0xff) * norm,
			     ((rgba >> 8) & 0xff) * norm,
			     (rgba & 0xff) * norm);
}

static void
draw_dot(CGContextRef ctx, double x, double y, double r,
	 unsigned int rgba)
{
    cgcontext_set_rgba(ctx, rgba);
    CGMutablePathRef path = CGPathCreateMutable();
    CGPathAddArc(path, NULL, x, y, r, 0, 2 * M_PI, false);
    CGContextAddPath(ctx, path);
    CGPathRelease(path);
    CGContextFillPath(ctx);
}

static void
draw_raw_rect(CGContextRef ctx, double x0, double y0, double x1, double y1,
	      unsigned int rgba)
{
    HIRect rect;

    cgcontext_set_rgba(ctx, rgba);
    rect.origin.x = x0;
    rect.origin.y = y0;
    rect.size.width = x1 - x0;
    rect.size.height = y1 - y0;
    CGContextFillRect(ctx, rect);
}

static void
draw_rect(CGContextRef ctx, double x, double y, double r,
	 unsigned int rgba)
{
    draw_raw_rect(ctx, x - r, y - r, x + r, y + r, rgba);
}

static OSStatus
view_draw(EventRef inEvent, viewctx *ctx)
{
    OSStatus err;
    CGContextRef gc;
    CGDataProviderRef provider;
    CGImageRef image;
    CGColorSpaceRef colorspace;
    CGRect rect;

    err = GetEventParameter(inEvent, kEventParamCGContextRef, typeCGContextRef,
			    NULL, sizeof(CGContextRef), NULL, &gc);
    require_noerr(err, cleanup);

    colorspace = CGColorSpaceCreateDeviceRGB();
    provider = CGDataProviderCreateWithData(NULL, ctx->image->samples,
					    ctx->image->w * ctx->image->h * 4,
					    NULL);
    image = CGImageCreate(ctx->image->w, ctx->image->h,
			  8, 32, ctx->image->w * 4,
			  colorspace, kCGImageAlphaNoneSkipFirst, provider,
			  NULL, 0, kCGRenderingIntentDefault);

    rect.origin.x = 0;
    rect.origin.y = 0;
    rect.size.width = ctx->image->w;
    rect.size.height = ctx->image->h;
    HIViewDrawCGImage(gc, &rect, image);

    CGColorSpaceRelease(colorspace);
    CGDataProviderRelease(provider);

 cleanup:
    return err;
}

static OSStatus
view_get_data(EventRef inEvent, viewctx *inData)
{
    OSStatus err;
    OSType tag;
    Ptr ptr;
    Size outSize;

    /* Probably could use a bit more error checking here, for type
       and size match. Also, just returning a viewctx seems a
       little hacky. */
    err = GetEventParameter(inEvent, kEventParamControlDataTag, typeEnumeration,
			    NULL, sizeof(OSType), NULL, &tag);
    require_noerr(err, ParameterMissing);

    err = GetEventParameter(inEvent, kEventParamControlDataBuffer, typePtr,
			    NULL, sizeof(Ptr), NULL, &ptr);

    if (tag == kViewPrivate) {
	*((viewctx **)ptr) = inData;
	outSize = sizeof(viewctx *);
    } else
	err = errDataNotSupported;

    if (err == noErr)
	err = SetEventParameter(inEvent, kEventParamControlDataBufferSize, typeLongInteger,
				sizeof(Size), &outSize);

 ParameterMissing:
    return err;
}

static OSStatus
view_set_data(EventRef inEvent, viewctx *inData)
{
    OSStatus err;
    Ptr ptr;
    OSType tag;

    err = GetEventParameter(inEvent, kEventParamControlDataTag, typeEnumeration,
			    NULL, sizeof(OSType), NULL, &tag);
    require_noerr(err, ParameterMissing);

    err = GetEventParameter(inEvent, kEventParamControlDataBuffer, typePtr,
			    NULL, sizeof(Ptr), NULL, &ptr);
    require_noerr(err, ParameterMissing);

    if (tag == 'Plat') {
	//inData->p = *(plate **)ptr;
    } else
	err = errDataNotSupported;

 ParameterMissing:
    return err;
}

static OSStatus
view_hittest(EventRef inEvent, viewctx *inData)
{
    OSStatus err;
    HIPoint where;
    HIRect bounds;
    ControlPartCode part;

    err = GetEventParameter(inEvent, kEventParamMouseLocation, typeHIPoint,
			    NULL, sizeof(HIPoint), NULL, &where);
    require_noerr(err, ParameterMissing);

    err = HIViewGetBounds(inData->view, &bounds);
    require_noerr(err, ParameterMissing);

    if (CGRectContainsPoint(bounds, where))
	part = 1;
    else
	part = kControlNoPart;
    err = SetEventParameter(inEvent, kEventParamControlPart,
			    typeControlPartCode, sizeof(ControlPartCode),
			    &part);
    printf("hittest %g, %g!\n", where.x, where.y);

 ParameterMissing:
    return err;
}

static void
view_queue_draw(viewctx *pe)
{
    HIViewSetNeedsDisplay(pe->view, true);
}


static int
view_motion(viewctx *pe, double x, double y)
{
    //if (pe->p->motmode == MOTION_MODE_MOVE)
    //plate_motion_move(pe->p, x, y);
    //else if (pe->p->motmode == MOTION_MODE_SELECT)
    //plate_motion_select(pe->p, x, y);
    view_queue_draw(pe);
    return 1;
}

static int
view_button_release(viewctx *pe)
{
    int need_redraw;
    
    //need_redraw = (pe->p->motmode == MOTION_MODE_SELECT);

    //plate_unpress(pe->p);

    if (need_redraw)
	view_queue_draw(pe);
    return 1;
}

pascal OSStatus
view_handler(EventHandlerCallRef inCallRef,
		EventRef inEvent,
		void* inUserData )
{
    OSStatus err = eventNotHandledErr;
    UInt32 eventClass = GetEventClass(inEvent);
    UInt32 eventKind = GetEventKind(inEvent);
    viewctx *data = (viewctx *)inUserData;

    switch (eventClass) {
    case kEventClassHIObject:
	switch (eventKind) {
	case kEventHIObjectConstruct:
	    err = view_construct(inEvent);
	    break;
	case kEventHIObjectInitialize:
	    err = view_initialize(inCallRef, inEvent, data);
	    break;
	case kEventHIObjectDestruct:
	    err = view_destruct(inEvent, data);
	    break;
	}
	break;
    case kEventClassControl:
	switch (eventKind) {
	case kEventControlInitialize:
	    err = noErr;
	    break;
	case kEventControlDraw:
	    err = view_draw(inEvent, data);
	    break;
	case kEventControlGetData:
	    err = view_get_data(inEvent, data);
	    break;
	case kEventControlSetData:
	    err = view_set_data(inEvent, data);
	    break;
	case kEventControlHitTest:
	    err = view_hittest(inEvent, data);
	    break;
	    /*...*/
	}
	break;
    }
    return err;
}

OSStatus
view_register(void)
{
    OSStatus err = noErr;
    static HIObjectClassRef view_ClassRef = NULL;

    if (view_ClassRef == NULL) {
	EventTypeSpec eventList[] = {
	    { kEventClassHIObject, kEventHIObjectConstruct },
	    { kEventClassHIObject, kEventHIObjectInitialize },
	    { kEventClassHIObject, kEventHIObjectDestruct },

	    { kEventClassControl, kEventControlActivate },
	    { kEventClassControl, kEventControlDeactivate },
	    { kEventClassControl, kEventControlDraw },
	    { kEventClassControl, kEventControlHiliteChanged },
	    { kEventClassControl, kEventControlHitTest },
	    { kEventClassControl, kEventControlInitialize },
	    { kEventClassControl, kEventControlGetData },
	    { kEventClassControl, kEventControlSetData },
	};
	err = HIObjectRegisterSubclass(kViewClassID,
				       kHIViewClassID,
				       NULL,
				       view_handler,
				       GetEventTypeCount(eventList),
				       eventList,
				       NULL,
				       &view_ClassRef);
    }
    return err;
}

OSStatus view_create(
	WindowRef			inWindow,
	const HIRect*		inBounds,
	HIViewRef*			outView)
{
    OSStatus err;
    EventRef event;

    err = view_register();
    require_noerr(err, CantRegister);

    err = CreateEvent(NULL, kEventClassHIObject, kEventHIObjectInitialize,
		      GetCurrentEventTime(), 0, &event);
    require_noerr(err, CantCreateEvent);

    if (inBounds != NULL) {
	err = SetEventParameter(event, 'Boun', typeHIRect, sizeof(HIRect),
				inBounds);
	require_noerr(err, CantSetParameter);
    }

    err = HIObjectCreate(kViewClassID, event, (HIObjectRef*)outView);
    require_noerr(err, CantCreate);

    if (inWindow != NULL) {
	HIViewRef root;
	err = GetRootControl(inWindow, &root);
	require_noerr(err, CantGetRootView);
	err = HIViewAddSubview(root, *outView);
    }
 CantCreate:
 CantGetRootView:
 CantSetParameter:
 CantCreateEvent:
    ReleaseEvent(event);
 CantRegister:
    return err;
}

OSStatus
view_openpdf(HIViewRef view, char *filename)
{
    OSStatus err;
    viewctx *ctx;

    err = GetControlData(view, 1, kViewPrivate, 4, &ctx, NULL);
    require_noerr(err, CantGetPrivate);

	fz_error *error;
	fz_obj *obj;
	pdf_xref *xref;

	error = pdf_newxref(&xref);
	if (error)
		fz_abort(error);
	ctx->xref = xref;

	error = pdf_loadxref(xref, filename);
	if (error)
	{
		fz_warn(error->msg);
		printf("trying to repair...\n");
		error = pdf_repairxref(xref, filename);
		if (error)
			fz_abort(error);
	}

	error = pdf_decryptxref(xref);
	if (error)
		fz_abort(error);

#if 0
	if (xref->crypt)
	{
		error = pdf_setpassword(xref->crypt, password);
		if (error) fz_abort(error);
	}
#endif

	obj = fz_dictgets(xref->trailer, "Root");
	if (!obj)
		fz_abort(fz_throw("syntaxerror: missing Root object"));
	error = pdf_loadindirect(&xref->root, xref, obj);
	if (error) fz_abort(error);

	obj = fz_dictgets(xref->trailer, "Info");
	if (obj)
	{
		error = pdf_loadindirect(&xref->info, xref, obj);
		if (error) fz_abort(error);
	}

	error = pdf_loadnametrees(xref);
	if (error) fz_abort(error);

	error = pdf_loadoutline(&ctx->outline, xref);
	if (error) fz_abort(error);

	ctx->doctitle = filename;
	if (xref->info)
	{
		obj = fz_dictgets(xref->info, "Title");
		if (obj)
		{
			error = pdf_toutf8(&ctx->doctitle, obj);
			if (error) fz_abort(error);
		}
	}

	error = pdf_loadpagetree(&ctx->pages, xref);
	if (error) fz_abort(error);

	//count = pdf_getpagecount(ctx->pages);

	error = fz_newrenderer(&ctx->rast, pdf_devicergb, 0, 1024 * 512);
	if (error) fz_abort(error);

	ctx->image = nil;
	printf("hit bottom\n");


 CantGetPrivate:
    return err;
}

OSStatus view_showpage(HIViewRef view)
{
    OSStatus err;
    viewctx *ctx;

    err = GetControlData(view, 1, kViewPrivate, 4, &ctx, NULL);
    require_noerr(err, CantGetPrivate);

	fz_error *error;
	fz_matrix ctm;
	fz_rect bbox;
	fz_obj *obj;
	char s[256];

	assert(ctx->pageno > 0 && ctx->pageno <= pdf_getpagecount(ctx->pages));

	//XDefineCursor(xdpy, xwin, xcwait);

	if (ctx->image)
		fz_droppixmap(ctx->image);
	ctx->image = nil;

	obj = pdf_getpageobject(ctx->pages, ctx->pageno - 1);
	if (obj == ctx->pageobj)
		goto Lskipload;
	ctx->pageobj = obj;

	if (ctx->page)
		pdf_droppage(ctx->page);

	error = pdf_loadpage(&ctx->page, ctx->xref, ctx->pageobj);
	if (error)
		fz_abort(error);

Lskipload:

	ctm = fz_identity();
	ctm = fz_concat(ctm, fz_translate(0, -ctx->page->mediabox.max.y));
	ctm = fz_concat(ctm, fz_scale(ctx->zoom, -ctx->zoom));
	ctm = fz_concat(ctm, fz_rotate(ctx->rotate + ctx->page->rotate));

	bbox = fz_transformaabb(ctm, ctx->page->mediabox);

	error = fz_rendertree(&ctx->image, ctx->rast, ctx->page->tree, ctm, fz_roundrect(bbox), 1);
	if (error)
		fz_abort(error);

	//XDefineCursor(xdpy, xwin, xcarrow);

	{
		char buf[512];
		int count = pdf_getpagecount(ctx->pages);
		sprintf(buf, "%s - %d/%d", ctx->doctitle, ctx->pageno, count);
		//xtitle(buf);
	}

	//xresize();
	//xblit();
 CantGetPrivate:
	return err;
}

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

    openpdf(window, "/Users/tor/src/pdf/tiger.pdf");

    DisposeNibReference(nibRef);

    ShowWindow(window);
    RunApplicationEventLoop();

 CantGetNibRef:
 CantSetMenuBar:
 CantCreateWindow:
 CantRegisterView:

    return err;
}
