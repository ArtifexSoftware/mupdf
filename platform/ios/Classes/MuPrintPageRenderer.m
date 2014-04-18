//
//  MuPrintPageRenderer.m
//  MuPDF
//
//  Copyright (c) 2014 Artifex Software, Inc. All rights reserved.
//

#include "common.h"
#import "MuPrintPageRenderer.h"

@implementation MuPrintPageRenderer

-(id) initWithDocRef:(MuDocRef *)aDocRef
{
	self = [super init];
	if (self)
	{
		docRef = [aDocRef retain];
	}
	return  self;
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
			npages = fz_count_pages(docRef->doc);
		}
		fz_catch(ctx);
	});
	return npages;
}

-(void) drawPageAtIndex:(NSInteger)pageIndex inRect:(CGRect)printableRect
{
	CGContextRef cgctx = UIGraphicsGetCurrentContext();

	if (!cgctx) return;

	CGSize paperSize = self.paperRect.size;
	// We must perform mupdf calls within this function, but all library calls need
	// to be on our background thread, so we run them synchronously on the queue

	__block fz_pixmap *pix = NULL;
	__block CGSize pageSize;
	dispatch_sync(queue, ^{
		fz_page *page = NULL;
		fz_device *dev = NULL;
		fz_var(page);
		fz_var(dev);
		fz_try(ctx)
		{
			fz_rect bounds;
			fz_matrix ctm;
			page = fz_load_page(docRef->doc, pageIndex);
			fz_bound_page(docRef->doc, page, &bounds);
			pageSize.width = bounds.x1 - bounds.x0;
			pageSize.height = bounds.y1 - bounds.y0;
			CGSize scale = fitPageToScreen(pageSize, paperSize);
			pageSize.width = roundf(pageSize.width * scale.width);
			pageSize.height = roundf(pageSize.height * scale.height);
			// Need to render upside down. No idea why.
			fz_scale(&ctm, scale.width, -scale.height);
			fz_pre_translate(&ctm, 0, -pageSize.height);
			pix = fz_new_pixmap(ctx, fz_device_rgb(ctx), pageSize.width, pageSize.height);
			fz_clear_pixmap_with_value(ctx, pix, 255);
			dev = fz_new_draw_device(ctx, pix);
			fz_run_page(docRef->doc, page, dev, &ctm, NULL);
		}
		fz_always(ctx)
		{
			fz_free_page(docRef->doc, page);
			fz_free_device(dev);
		}
		fz_catch(ctx)
		{
			printf("Failed to print page %d\n", pageIndex+1);
		}
	});

	if (!pix) return;

	CGRect rect = {{0.0,0.0},pageSize};
	CGDataProviderRef dataref = wrapPixmap(pix);
	CGImageRef img = newCGImageWithPixmap(pix, dataref);
	CGContextDrawImage(cgctx, rect, img);
	CGImageRelease(img);
	CGDataProviderRelease(dataref); //releases pix
}

@end
