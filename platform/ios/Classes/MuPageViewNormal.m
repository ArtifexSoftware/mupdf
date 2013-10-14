//
//  MuPageView.m
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#include "common.h"
#include "mupdf/pdf.h"
#import "MuTextFieldController.h"

static void releasePixmap(void *info, const void *data, size_t size)
{
	if (queue)
		dispatch_async(queue, ^{
			fz_drop_pixmap(ctx, info);
		});
	else
	{
		fz_drop_pixmap(ctx, info);
	}
}

static CGDataProviderRef wrapPixmap(fz_pixmap *pix)
{
	unsigned char *samples = fz_pixmap_samples(ctx, pix);
	int w = fz_pixmap_width(ctx, pix);
	int h = fz_pixmap_height(ctx, pix);
	return CGDataProviderCreateWithData(pix, samples, w * 4 * h, releasePixmap);
}

static UIImage *newImageWithPixmap(fz_pixmap *pix, CGDataProviderRef cgdata)
{
	int w = fz_pixmap_width(ctx, pix);
	int h = fz_pixmap_height(ctx, pix);
	CGColorSpaceRef cgcolor = CGColorSpaceCreateDeviceRGB();
	CGImageRef cgimage = CGImageCreate(w, h, 8, 32, 4 * w,
                                       cgcolor, kCGBitmapByteOrderDefault,
                                       cgdata, NULL, NO, kCGRenderingIntentDefault);
	UIImage *image = [[UIImage alloc]
                      initWithCGImage: cgimage
                      scale: screenScale
                      orientation: UIImageOrientationUp];
	CGColorSpaceRelease(cgcolor);
	CGImageRelease(cgimage);
	return image;
}

static NSArray *enumerateWidgetRects(fz_document *doc, fz_page *page, CGSize pageSize, CGSize screenSize)
{
	pdf_document *idoc = pdf_specifics(doc);
	pdf_widget *widget;
	NSMutableArray *arr = [NSMutableArray arrayWithCapacity:10];
	CGSize scale = fitPageToScreen(pageSize, screenSize);

	if (!idoc)
		return  nil;

	for (widget = pdf_first_widget(idoc, (pdf_page *)page); widget; widget = pdf_next_widget(widget))
	{
		fz_rect rect;

		pdf_bound_widget(widget, &rect);
		[arr addObject:[NSValue valueWithCGRect:CGRectMake(
			rect.x0 * scale.width,
			rect.y0 * scale.height,
			(rect.x1-rect.x0) * scale.width,
			(rect.y1-rect.y0) * scale.height)]];
	}

	return [arr retain];
}

static int setFocussedWidgetText(fz_document *doc, fz_page *page, const char *text)
{
	int accepted;

	fz_try(ctx)
	{
		pdf_document *idoc = pdf_specifics(doc);
		if (idoc)
		{
			pdf_widget *focus = pdf_focused_widget(idoc);
			if (focus)
			{
				accepted = pdf_text_widget_set_text(idoc, focus, (char *)text);
			}
		}
	}
	fz_catch(ctx)
	{
		accepted = 0;
	}

	return accepted;
}

static int setFocussedWidgetChoice(fz_document *doc, fz_page *page, const char *text)
{
	int accepted;

	fz_try(ctx)
	{
		pdf_document *idoc = pdf_specifics(doc);
		if (idoc)
		{
			pdf_widget *focus = pdf_focused_widget(idoc);
			if (focus)
			{
				pdf_choice_widget_set_value(idoc, focus, 1, (char **)&text);
				accepted = 1;
			}
		}
	}
	fz_catch(ctx)
	{
		accepted = 0;
	}

	return accepted;
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
		pdf_document *idoc = pdf_specifics(doc);

		if (idoc)
			pdf_update_page(idoc, (pdf_page *)page);
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

static fz_pixmap *renderPixmap(fz_document *doc, fz_display_list *page_list, fz_display_list *annot_list, CGSize pageSize, CGSize screenSize, CGRect tileRect, float zoom)
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
		return NULL;
	}

	return pix;
}

typedef struct rect_list_s rect_list;

struct rect_list_s
{
	fz_rect rect;
	rect_list *next;
};

static void drop_list(rect_list *list)
{
	while (list)
	{
		rect_list *n = list->next;
		fz_free(ctx, list);
		list = n;
	}
}

static rect_list *updatePage(fz_document *doc, fz_page *page)
{
	rect_list *list = NULL;

	fz_var(list);
	fz_try(ctx)
	{
		pdf_document *idoc = pdf_specifics(doc);

		if (idoc)
		{
			fz_annot *annot;

			pdf_update_page(idoc, (pdf_page *)page);
			while ((annot = (fz_annot *)pdf_poll_changed_annot(idoc, (pdf_page *)page)) != NULL)
			{
				rect_list *node = fz_malloc_struct(ctx, rect_list);

				fz_bound_annot(doc, annot, &node->rect);
				node->next = list;
				list = node;
			}
		}
	}
	fz_catch(ctx)
	{
		drop_list(list);
		list = NULL;
	}

	return list;
}

static void updatePixmap(fz_document *doc, fz_display_list *page_list, fz_display_list *annot_list, fz_pixmap *pixmap, rect_list *rlist, CGSize pageSize, CGSize screenSize, CGRect tileRect, float zoom)
{
	fz_irect bbox;
	fz_rect rect;
	fz_matrix ctm;
	fz_device *dev = NULL;
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
	fz_try(ctx)
	{
		while (rlist)
		{
			fz_irect abox;
			fz_rect arect = rlist->rect;
			fz_transform_rect(&arect, &ctm);
			fz_intersect_rect(&arect, &rect);
			fz_round_rect(&abox, &arect);
			if (!fz_is_empty_irect(&abox))
			{
				fz_clear_pixmap_rect_with_value(ctx, pixmap, 255, &abox);
				dev = fz_new_draw_device_with_bbox(ctx, pixmap, &abox);
				fz_run_display_list(page_list, dev, &ctm, &arect, NULL);
				fz_run_display_list(annot_list, dev, &ctm, &arect, NULL);
				fz_free_device(dev);
				dev = NULL;
			}
			rlist = rlist->next;
		}
	}
	fz_always(ctx)
	{
		fz_free_device(dev);
	}
	fz_catch(ctx)
	{
	}
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

-(id) initWithFrame:(CGRect)frame dialogCreator:(id<MuDialogCreator>)dia document:(MuDocRef *)aDoc page:(int)aNumber
{
	self = [super initWithFrame: frame];
	if (self) {
		docRef = [aDoc retain];
		doc = docRef->doc;
		number = aNumber;
		cancel = NO;
		dialogCreator = dia;

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
		__block CGDataProviderRef block_tileData = tileData;
		__block CGDataProviderRef block_imageData = imageData;
		dispatch_async(queue, ^{
			if (block_page_list)
				fz_drop_display_list(ctx, block_page_list);
			if (block_annot_list)
				fz_drop_display_list(ctx, block_annot_list);
			if (block_page)
				fz_free_page(block_doc, block_page);
			block_page = nil;
			CGDataProviderRelease(block_tileData);
			CGDataProviderRelease(block_imageData);
		});
		[docRef release];
		[widgetRects release];
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
			image_pix = renderPixmap(doc, page_list, annot_list, pageSize, self.bounds.size, rect, 1.0);
			CGDataProviderRelease(imageData);
			imageData = wrapPixmap(image_pix);
			UIImage *image = newImageWithPixmap(image_pix, imageData);
			widgetRects = enumerateWidgetRects(doc, page, pageSize, self.bounds.size);
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

	if (imageView)
	{
		if (hitView)
			[hitView setFrame: [imageView frame]];

		if (linkView)
			[linkView setFrame:[imageView frame]];
	}
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
		tile_pix = renderPixmap(doc, page_list, annot_list, pageSize, screenSize, viewFrame, scale);
		CGDataProviderRelease(tileData);
		tileData = wrapPixmap(tile_pix);
		UIImage *image = newImageWithPixmap(tile_pix, tileData);

		dispatch_async(dispatch_get_main_queue(), ^{
			isValid = CGRectEqualToRect(frame, tileFrame) && scale == tileScale;
			if (isValid) {
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
				if (linkView)
					[self bringSubviewToFront:linkView];
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

- (void) updatePageAndTileWithTileFrame:(CGRect)tframe tileScale:(float)tscale viewFrame:(CGRect)vframe
{
	rect_list *rlist = updatePage(doc, page);
	fz_drop_display_list(ctx, annot_list);
	annot_list = create_annot_list(doc, page);
	if (tile_pix)
	{
		updatePixmap(doc, page_list, annot_list, tile_pix, rlist, pageSize, self.bounds.size, vframe, tscale);
		UIImage *timage = newImageWithPixmap(tile_pix, tileData);
		dispatch_async(dispatch_get_main_queue(), ^{
			BOOL isValid = CGRectEqualToRect(tframe, tileFrame) && tscale == tileScale;
			if (isValid)
				[tileView setImage:timage];
			[timage release];
		});
	}
	CGSize fscale = fitPageToScreen(pageSize, self.bounds.size);
	CGRect rect = (CGRect){{0.0, 0.0},{pageSize.width * fscale.width, pageSize.height * fscale.height}};
	updatePixmap(doc, page_list, annot_list, image_pix, rlist,  pageSize, self.bounds.size, rect, 1.0);
	drop_list(rlist);
	UIImage *image = newImageWithPixmap(image_pix, imageData);
	dispatch_async(dispatch_get_main_queue(), ^{
		[imageView setImage:image];
		[image release];
	});
}

- (void) invokeTextDialog:(NSString *)text
{
	[dialogCreator invokeTextDialog:text okayAction:^(NSString *newText) {
		CGRect tframe = tileFrame;
		float tscale = tileScale;
		CGRect vframe = tframe;
		vframe.origin.x -= imageView.frame.origin.x;
		vframe.origin.y -= imageView.frame.origin.y;

		dispatch_async(queue, ^{
			BOOL accepted = setFocussedWidgetText(doc, page, [newText UTF8String]);
			if (accepted)
			{
				[self updatePageAndTileWithTileFrame:tframe tileScale:tscale viewFrame:vframe];
			}
			else
			{
				dispatch_async(dispatch_get_main_queue(), ^{
					[self invokeTextDialog:newText];
				});
			}
		});
	}];
}

- (void) invokeChoiceDialog:(NSArray *)choices
{
	[dialogCreator invokeChoiceDialog:choices okayAction:^(NSArray *selection) {
		CGRect tframe = tileFrame;
		float tscale = tileScale;
		CGRect vframe = tframe;
		vframe.origin.x -= imageView.frame.origin.x;
		vframe.origin.y -= imageView.frame.origin.y;

		dispatch_async(queue, ^{
			BOOL accepted = setFocussedWidgetChoice(doc, page, [[selection objectAtIndex:0] UTF8String]);
			if (accepted)
			{
				[self updatePageAndTileWithTileFrame:tframe tileScale:tscale viewFrame:vframe];
			}
			else
			{
				dispatch_async(dispatch_get_main_queue(), ^{
					[self invokeChoiceDialog:choices];
				});
			}
		});

	}];
}

- (int) passTapToPage:(CGPoint)pt
{
	pdf_document *idoc = pdf_specifics(doc);
	CGSize scale = fitPageToScreen(pageSize, self.bounds.size);
	pdf_ui_event event;
	int changed = 0;
	pdf_widget *focus;
	char **opts = NULL;
	char *text = NULL;

	if (!idoc)
		return;

	fz_var(opts);
	fz_var(text);
	fz_try(ctx)
	{
		event.etype = PDF_EVENT_TYPE_POINTER;
		event.event.pointer.pt.x = pt.x / scale.width;
		event.event.pointer.pt.y = pt.y / scale.height;
		event.event.pointer.ptype = PDF_POINTER_DOWN;
		changed = pdf_pass_event(idoc, (pdf_page *)page, &event);
		event.event.pointer.ptype = PDF_POINTER_UP;
		changed |= pdf_pass_event(idoc, (pdf_page *)page, &event);

		focus = pdf_focused_widget(idoc);
		if (focus)
		{
			switch (pdf_widget_get_type(focus))
			{
				case PDF_WIDGET_TYPE_TEXT:
				{
					text = pdf_text_widget_text(idoc, focus);
					NSString *stext = [[NSString stringWithUTF8String:text?text:""] retain];
					dispatch_async(dispatch_get_main_queue(), ^{
						[self invokeTextDialog:stext];
						[stext release];
					});
					break;
				}

				case PDF_WIDGET_TYPE_LISTBOX:
				case PDF_WIDGET_TYPE_COMBOBOX:
				{
					int nopts = pdf_choice_widget_options(idoc, focus, NULL);
					opts = fz_malloc(ctx, nopts * sizeof(*opts));
					(void)pdf_choice_widget_options(idoc, focus, opts);
					NSMutableArray *arr = [[NSMutableArray arrayWithCapacity:nopts] retain];
					for (int i = 0; i < nopts; i++)
						[arr addObject:[NSString stringWithUTF8String:opts[i]]];
					dispatch_async(dispatch_get_main_queue(), ^{
						[self invokeChoiceDialog:arr];
						[arr release];
					});
					break;
				}

				case PDF_WIDGET_TYPE_SIGNATURE:
					break;

				default:
					break;
			}
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, text);
		fz_free(ctx, opts);
	}
	fz_catch(ctx)
	{
	}

	return changed;
}

- (MuTapResult *) handleTap:(CGPoint)pt
{
	CGPoint ipt = [self convertPoint:pt toView:imageView];
	for (int i = 0; i < widgetRects.count; i++)
	{
		CGRect r = [[widgetRects objectAtIndex:i] CGRectValue];
		if (CGRectContainsPoint([[widgetRects objectAtIndex:i] CGRectValue], ipt))
		{
			CGRect tframe = tileFrame;
			float tscale = tileScale;
			CGRect vframe = tframe;
			vframe.origin.x -= imageView.frame.origin.x;
			vframe.origin.y -= imageView.frame.origin.y;

			dispatch_async(queue, ^{
				int changed = [self passTapToPage:ipt];
				if (changed)
					[self updatePageAndTileWithTileFrame:tframe tileScale:tscale viewFrame:vframe];
			});
			return [[[MuTapResultWidget alloc] init] autorelease];
		}
	}
	CGPoint lpt = [self convertPoint:pt toView:linkView];
	return linkView ? [linkView handleTap:lpt] : nil;
}

@end
