//
//  MuPageView.m
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#include "common.h"

static void releasePixmap(void *info, const void *data, size_t size)
{
	if (queue)
		dispatch_async(queue, ^{
			fz_drop_pixmap(ctx, info);
		});
	else
		fz_drop_pixmap(ctx, info);
}

static UIImage *newImageWithPixmap(fz_pixmap *pix)
{
	unsigned char *samples = fz_pixmap_samples(ctx, pix);
	int w = fz_pixmap_width(ctx, pix);
	int h = fz_pixmap_height(ctx, pix);
	CGDataProviderRef cgdata = CGDataProviderCreateWithData(pix, samples, w * 4 * h, releasePixmap);
	CGColorSpaceRef cgcolor = CGColorSpaceCreateDeviceRGB();
	CGImageRef cgimage = CGImageCreate(w, h, 8, 32, 4 * w,
                                       cgcolor, kCGBitmapByteOrderDefault,
                                       cgdata, NULL, NO, kCGRenderingIntentDefault);
	UIImage *image = [[UIImage alloc]
                      initWithCGImage: cgimage
                      scale: screenScale
                      orientation: UIImageOrientationUp];
	CGDataProviderRelease(cgdata);
	CGColorSpaceRelease(cgcolor);
	CGImageRelease(cgimage);
	return image;
}

static fz_display_list *create_page_list(fz_document *doc, fz_page *page)
{
	fz_display_list *list;
	fz_device *dev = NULL;

	fz_var(dev);
	fz_try(ctx)
	{
		list = fz_new_display_list(ctx);
		dev = fz_new_list_device(ctx, list);
		fz_run_page_contents(doc, page, dev, &fz_identity, NULL);
	}
	fz_always(ctx)
	{
		fz_free_device(dev);
	}
	fz_catch(ctx)
	{
		return NULL;
	}

	return list;
}

static fz_display_list *create_annot_list(fz_document *doc, fz_page *page)
{
	fz_display_list *list;
	fz_device *dev = NULL;

	fz_var(dev);
	fz_try(ctx)
	{
		fz_annot *annot;

		list = fz_new_display_list(ctx);
		dev = fz_new_list_device(ctx, list);
		for (annot = fz_first_annot(doc, page); annot; annot = fz_next_annot(doc, annot))
			fz_run_annot(doc, page, annot, dev, &fz_identity, NULL);
	}
	fz_always(ctx)
	{
		fz_free_device(dev);
	}
	fz_catch(ctx)
	{
		return NULL;
	}

	return list;
}

static UIImage *renderPage(fz_document *doc, fz_display_list *page_list, fz_display_list *annot_list, CGSize pageSize, CGSize screenSize, CGRect tileRect, float zoom)
{
	fz_irect bbox;
	fz_rect rect;
	fz_matrix ctm;
	fz_device *dev = NULL;
	fz_pixmap *pix = NULL;
	CGSize scale;

	screenSize.width *= screenScale;
	screenSize.height *= screenScale;
	tileRect.origin.x *= screenScale;
	tileRect.origin.y *= screenScale;
	tileRect.size.width *= screenScale;
	tileRect.size.height *= screenScale;

	scale = fitPageToScreen(pageSize, screenSize);
	fz_scale(&ctm, scale.width * zoom, scale.height * zoom);

	bbox.x0 = tileRect.origin.x;
	bbox.y0 = tileRect.origin.y;
	bbox.x1 = tileRect.origin.x + tileRect.size.width;
	bbox.y1 = tileRect.origin.y + tileRect.size.height;
	fz_rect_from_irect(&rect, &bbox);

	fz_var(dev);
	fz_var(pix);
	fz_try(ctx)
	{
		pix = fz_new_pixmap_with_bbox(ctx, fz_device_rgb(ctx), &bbox);
		fz_clear_pixmap_with_value(ctx, pix, 255);

		dev = fz_new_draw_device(ctx, pix);
		fz_run_display_list(page_list, dev, &ctm, &rect, NULL);
		fz_run_display_list(annot_list, dev, &ctm, &rect, NULL);
	}
	fz_always(ctx)
	{
		fz_free_device(dev);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, pix);
		return nil;
	}

	return newImageWithPixmap(pix);
}

#import "MuPageViewNormal.h"

@implementation MuPageViewNormal

- (void) ensurePageLoaded
{
	if (page)
		return;

	fz_try(ctx)
	{
		fz_rect bounds;
		page = fz_load_page(doc, number);
		fz_bound_page(doc, page, &bounds);
		pageSize.width = bounds.x1 - bounds.x0;
		pageSize.height = bounds.y1 - bounds.y0;
	}
	fz_catch(ctx)
	{
		return;
	}
}

- (void) ensureDisplaylists
{
	[self ensurePageLoaded];
	if (!page)
		return;

	if (!page_list)
		page_list = create_page_list(doc, page);

	if (!annot_list)
		annot_list = create_annot_list(doc, page);
}

- (id) initWithFrame: (CGRect)frame document: (MuDocRef *)aDoc page: (int)aNumber
{
	self = [super initWithFrame: frame];
	if (self) {
		docRef = [aDoc retain];
		doc = docRef->doc;
		number = aNumber;
		cancel = NO;

		[self setShowsVerticalScrollIndicator: NO];
		[self setShowsHorizontalScrollIndicator: NO];
		[self setDecelerationRate: UIScrollViewDecelerationRateFast];
		[self setDelegate: self];

		// zoomDidFinish/Begin events fire before bounce animation completes,
		// making a mess when we rearrange views during the animation.
		[self setBouncesZoom: NO];

		[self resetZoomAnimated: NO];

		// TODO: use a one shot timer to delay the display of this?
		loadingView = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
		[loadingView startAnimating];
		[self addSubview: loadingView];

		[self loadPage];
	}
	return self;
}

- (void) dealloc
{
	// dealloc can trigger in background thread when the queued block is
	// our last owner, and releases us on completion.
	// Send the dealloc back to the main thread so we don't mess up UIKit.
	if (dispatch_get_current_queue() != dispatch_get_main_queue()) {
		__block id block_self = self; // don't auto-retain self!
		dispatch_async(dispatch_get_main_queue(), ^{ [block_self dealloc]; });
	} else {
		__block fz_display_list *block_page_list = page_list;
		__block fz_display_list *block_annot_list = annot_list;
		__block fz_page *block_page = page;
		__block fz_document *block_doc = docRef->doc;
		dispatch_async(queue, ^{
			if (block_page_list)
				fz_drop_display_list(ctx, block_page_list);
			if (block_annot_list)
				fz_drop_display_list(ctx, block_annot_list);
			if (block_page)
				fz_free_page(block_doc, block_page);
			block_page = nil;
		});
		[docRef release];
		[linkView release];
		[hitView release];
		[tileView release];
		[loadingView release];
		[imageView release];
		[super dealloc];
	}
}

- (int) number
{
	return number;
}

- (void) showLinks
{
	if (!linkView) {
		dispatch_async(queue, ^{
			[self ensurePageLoaded];
			fz_link *links = fz_load_links(doc, page);
			dispatch_async(dispatch_get_main_queue(), ^{
				linkView = [[MuHitView alloc] initWithLinks: links forDocument: doc];
				dispatch_async(queue, ^{
					fz_drop_link(ctx, links);
				});
				if (imageView) {
					[linkView setFrame: [imageView frame]];
					[linkView setPageSize: pageSize];
				}
				[self addSubview: linkView];
			});
		});
	}
}

- (void) hideLinks
{
	[linkView removeFromSuperview];
	[linkView release];
	linkView = nil;
}

- (void) showSearchResults: (int)count
{
	if (hitView) {
		[hitView removeFromSuperview];
		[hitView release];
		hitView = nil;
	}
	hitView = [[MuHitView alloc] initWithSearchResults: count forDocument: doc];
	if (imageView) {
		[hitView setFrame: [imageView frame]];
		[hitView setPageSize: pageSize];
	}
	[self addSubview: hitView];
}

- (void) clearSearchResults
{
	if (hitView) {
		[hitView removeFromSuperview];
		[hitView release];
		hitView = nil;
	}
}

- (void) resetZoomAnimated: (BOOL)animated
{
	// discard tile and any pending tile jobs
	tileFrame = CGRectZero;
	tileScale = 1;
	if (tileView) {
		[tileView removeFromSuperview];
		[tileView release];
		tileView = nil;
	}

	[self setMinimumZoomScale: 1];
	[self setMaximumZoomScale: 5];
	[self setZoomScale: 1 animated: animated];
}

- (void) removeFromSuperview
{
	cancel = YES;
	[super removeFromSuperview];
}

- (void) loadPage
{
	if (number < 0 || number >= fz_count_pages(doc))
		return;
	dispatch_async(queue, ^{
		if (!cancel) {
			printf("render page %d\n", number);
			[self ensureDisplaylists];
			CGSize scale = fitPageToScreen(pageSize, self.bounds.size);
			CGRect rect = (CGRect){{0.0, 0.0},{pageSize.width * scale.width, pageSize.height * scale.height}};
			UIImage *image = renderPage(doc, page_list, annot_list, pageSize, self.bounds.size, rect, 1.0);
			dispatch_async(dispatch_get_main_queue(), ^{
				[self displayImage: image];
				[image release];
			});
		} else {
			printf("cancel page %d\n", number);
		}
	});
}

- (void) displayImage: (UIImage*)image
{
	if (loadingView) {
		[loadingView removeFromSuperview];
		[loadingView release];
		loadingView = nil;
	}

	if (hitView)
		[hitView setPageSize: pageSize];

	if (!imageView) {
		imageView = [[UIImageView alloc] initWithImage: image];
		imageView.opaque = YES;
		[self addSubview: imageView];
		if (hitView)
			[self bringSubviewToFront: hitView];
	} else {
		[imageView setImage: image];
	}

	[self resizeImage];
}

- (void) resizeImage
{
	if (imageView) {
		CGSize imageSize = imageView.image.size;
		CGSize scale = fitPageToScreen(imageSize, self.bounds.size);
		if (fabs(scale.width - 1) > 0.1) {
			CGRect frame = [imageView frame];
			frame.size.width = imageSize.width * scale.width;
			frame.size.height = imageSize.height * scale.height;
			[imageView setFrame: frame];

			printf("resized view; queuing up a reload (%d)\n", number);
			dispatch_async(queue, ^{
				dispatch_async(dispatch_get_main_queue(), ^{
					CGSize scale = fitPageToScreen(imageView.image.size, self.bounds.size);
					if (fabs(scale.width - 1) > 0.01)
						[self loadPage];
				});
			});
		} else {
			[imageView sizeToFit];
		}

		[self setContentSize: imageView.frame.size];

		[self layoutIfNeeded];
	}

}

- (void) willRotate
{
	if (imageView) {
		[self resetZoomAnimated: NO];
		[self resizeImage];
	}
}

- (void) layoutSubviews
{
	[super layoutSubviews];

	// center the image as it becomes smaller than the size of the screen

	CGSize boundsSize = self.bounds.size;
	CGRect frameToCenter = loadingView ? loadingView.frame : imageView.frame;

	// center horizontally
	if (frameToCenter.size.width < boundsSize.width)
		frameToCenter.origin.x = floor((boundsSize.width - frameToCenter.size.width) / 2);
	else
		frameToCenter.origin.x = 0;

	// center vertically
	if (frameToCenter.size.height < boundsSize.height)
		frameToCenter.origin.y = floor((boundsSize.height - frameToCenter.size.height) / 2);
	else
		frameToCenter.origin.y = 0;

	if (loadingView)
		loadingView.frame = frameToCenter;
	else
		imageView.frame = frameToCenter;

	if (hitView && imageView)
		[hitView setFrame: [imageView frame]];
}

- (UIView*) viewForZoomingInScrollView: (UIScrollView*)scrollView
{
	return imageView;
}

- (void) loadTile
{
	CGSize screenSize = self.bounds.size;

	tileFrame.origin = self.contentOffset;
	tileFrame.size = self.bounds.size;
	tileFrame = CGRectIntersection(tileFrame, imageView.frame);
	tileScale = self.zoomScale;

	CGRect frame = tileFrame;
	float scale = tileScale;

	CGRect viewFrame = frame;
	// Adjust viewFrame to be relative to imageView's origin
	viewFrame.origin.x -= imageView.frame.origin.x;
	viewFrame.origin.y -= imageView.frame.origin.y;

	if (scale < 1.01)
		return;

	dispatch_async(queue, ^{
		__block BOOL isValid;
		dispatch_sync(dispatch_get_main_queue(), ^{
			isValid = CGRectEqualToRect(frame, tileFrame) && scale == tileScale;
		});
		if (!isValid) {
			printf("cancel tile\n");
			return;
		}

		[self ensureDisplaylists];

		printf("render tile\n");
		UIImage *image = renderPage(doc, page_list, annot_list, pageSize, screenSize, viewFrame, scale);

		dispatch_async(dispatch_get_main_queue(), ^{
			isValid = CGRectEqualToRect(frame, tileFrame) && scale == tileScale;
			if (isValid) {
				tileFrame = CGRectZero;
				tileScale = 1;
				if (tileView) {
					[tileView removeFromSuperview];
					[tileView release];
					tileView = nil;
				}

				tileView = [[UIImageView alloc] initWithFrame: frame];
				[tileView setImage: image];
				[self addSubview: tileView];
				if (hitView)
					[self bringSubviewToFront: hitView];
			} else {
				printf("discard tile\n");
			}
			[image release];
		});
	});
}

- (void) scrollViewDidScrollToTop:(UIScrollView *)scrollView { [self loadTile]; }
- (void) scrollViewDidEndScrollingAnimation:(UIScrollView *)scrollView { [self loadTile]; }
- (void) scrollViewDidEndDecelerating:(UIScrollView *)scrollView { [self loadTile]; }
- (void) scrollViewDidEndDragging:(UIScrollView *)scrollView willDecelerate:(BOOL)decelerate
{
	if (!decelerate)
		[self loadTile];
}

- (void) scrollViewWillBeginZooming: (UIScrollView*)scrollView withView: (UIView*)view
{
	// discard tile and any pending tile jobs
	tileFrame = CGRectZero;
	tileScale = 1;
	if (tileView) {
		[tileView removeFromSuperview];
		[tileView release];
		tileView = nil;
	}
}

- (void) scrollViewDidEndZooming: (UIScrollView*)scrollView withView: (UIView*)view atScale: (float)scale
{
	[self loadTile];
}

- (void) scrollViewDidZoom: (UIScrollView*)scrollView
{
	if (hitView && imageView)
		[hitView setFrame: [imageView frame]];
}

- (void) setScale:(float)scale {}

@end
