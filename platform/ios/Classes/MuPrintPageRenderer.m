#include "common.h"
#import "MuPrintPageRenderer.h"

const int MaxStripPixels = 1024*1024;

@implementation MuPrintPageRenderer
{
	MuDocRef *docRef;
}

-(id) initWithDocRef:(MuDocRef *)aDocRef
{
	self = [super init];
	if (self)
	{
		docRef = [aDocRef retain];
	}
	return self;
}

-(void) dealloc
{
	[docRef release];
	[super dealloc];
}

-(NSInteger) numberOfPages
{
	__block NSInteger npages = 0;
	dispatch_sync(queue, ^{
		fz_try(ctx)
		{
			npages = fz_count_pages(ctx, docRef->doc);
		}
		fz_catch(ctx);
	});
	return npages;
}

static fz_page *getPage(fz_document *doc, NSInteger pageIndex)
{
	__block fz_page *page = NULL;

	dispatch_sync(queue, ^{
		fz_try(ctx)
		{
			page = fz_load_page(ctx, doc, (int)pageIndex);
		}
		fz_catch(ctx)
		{
			printf("Failed to load page\n");
		}
	});

	return page;
}

static CGSize getPageSize(fz_document *doc, fz_page *page)
{
	__block CGSize size = {0.0,0.0};

	dispatch_sync(queue, ^{
		fz_try(ctx)
		{
			fz_rect bounds;
			fz_bound_page(ctx, page, &bounds);
			size.width = bounds.x1 - bounds.x0;
			size.height = bounds.y1 - bounds.y0;
		}
		fz_catch(ctx)
		{
			printf("Failed to find page bounds\n");
		}
	});

	return size;
}

static fz_pixmap *createPixMap(CGSize size)
{
	__block fz_pixmap *pix = NULL;

	dispatch_sync(queue, ^{
		fz_try(ctx)
		{
			pix = fz_new_pixmap(ctx, fz_device_rgb(ctx), size.width, size.height);
		}
		fz_catch(ctx)
		{
			printf("Failed to create pixmap\n");
		}
	});

	return pix;
}

static void freePage(fz_document *doc, fz_page *page)
{
	dispatch_sync(queue, ^{
		fz_drop_page(ctx, page);
	});
}

static void renderPage(fz_document *doc, fz_page *page, fz_pixmap *pix, fz_matrix *ctm)
{
	dispatch_sync(queue, ^{
		fz_device *dev = NULL;
		fz_var(dev);
		fz_try(ctx)
		{
			dev = fz_new_draw_device(ctx, pix);
			fz_clear_pixmap_with_value(ctx, pix, 0xFF);
			fz_run_page(ctx, page, dev, ctm, NULL);
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
		}
		fz_catch(ctx)
		{
			printf("Failed to render page\n");
		}
	});
}

-(void) drawPageAtIndex:(NSInteger)pageIndex inRect:(CGRect)printableRect
{
	fz_page *page = NULL;
	fz_pixmap *pix = NULL;
	CGDataProviderRef dataref = NULL;
	CGImageRef img = NULL;
	CGContextRef cgctx = UIGraphicsGetCurrentContext();
	float dpi = 300.0;
	float ppi = 72.0;

	if (!cgctx) return;

	CGSize paperSize = self.paperRect.size;
	page = getPage(docRef->doc, pageIndex);
	if (page == NULL) return;

	CGSize pageSize = getPageSize(docRef->doc, page);
	if (pageSize.width == 0.0 || pageSize.height == 0.0)
		goto exit;

	CGSize scale = fitPageToScreen(pageSize, paperSize);
	pageSize.width *= scale.width;
	pageSize.height *= scale.height;

	CGSize pageSizePix = {roundf(pageSize.width * dpi / ppi), roundf(pageSize.height * dpi /ppi)};
	int max_strip_height = MaxStripPixels / (int)pageSizePix.width;
	if (pageSizePix.height > max_strip_height)
		pageSizePix.height = max_strip_height;
	CGSize stripSize = {pageSize.width, pageSizePix.height * ppi / dpi};

	float cursor = 0.0;

	while (cursor < pageSize.height)
	{
		// Overlap strips by 1 point
		if (cursor > 0.0)
			cursor -= 1.0;

		pix = createPixMap(pageSizePix);
		if (!pix)
			goto exit;

		dataref = CreateWrappedPixmap(pix);
		if (dataref == NULL)
			goto exit;

		img = CreateCGImageWithPixmap(pix, dataref);
		if (img == NULL)
			goto exit;

		fz_matrix ctm;
		fz_scale(&ctm, dpi / ppi, -dpi / ppi);
		fz_pre_translate(&ctm, 0, -stripSize.height-cursor);
		fz_pre_scale(&ctm, scale.width, scale.height);

		renderPage(docRef->doc, page, pix, &ctm);

		CGRect rect = {{0.0,cursor},stripSize};
		CGContextDrawImage(cgctx, rect, img);

		CGImageRelease(img);
		img = NULL;
		CGDataProviderRelease(dataref); // releases pix
		dataref = NULL;

		cursor += stripSize.height;
	}

exit:
	freePage(docRef->doc, page);
	CGImageRelease(img);
	CGDataProviderRelease(dataref); //releases pix
}

@end
