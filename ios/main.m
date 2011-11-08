#import <UIKit/UIKit.h>

// TODO: [[UIScreen mainScreen] scale]; -- for retina iphone 4 displays we want double resolution!

#undef ABS
#undef MIN
#undef MAX

#include "fitz/fitz.h"
#include "pdf/mupdf.h"
#include "xps/muxps.h"

#define GAP 20
#define INDICATOR_Y -44-24

static dispatch_queue_t queue;
static fz_glyph_cache *glyphcache = NULL;

@interface MuLibraryController : UITableViewController
{
	NSArray *files;
	NSTimer *timer;
}
- (void) openDocument: (NSString*)filename;
- (void) reload;
@end

@interface MuOutlineController : UITableViewController
{
	id target;
	NSMutableArray *titles;
	NSMutableArray *pages;
}
- (id) initWithTarget: (id)aTarget titles: (NSMutableArray*)aTitles pages: (NSMutableArray*)aPages;
@end

@interface MuPageView : UIScrollView <UIScrollViewDelegate>
{
	pdf_xref *xref;
	int number;
	UIActivityIndicatorView *loadingView;
	UIImageView *imageView;
	UIImageView *tileView;
	CGRect tileFrame;
	float tileScale;
	BOOL cancel;
}
- (id) initWithFrame: (CGRect)frame xref: (pdf_xref*)aXref page: (int)aNumber;
- (void) displayImage: (UIImage*)image;
- (void) resizeImage;
- (void) loadPage;
- (void) loadTile;
- (void) willRotate;
- (void) resetZoomAnimated: (BOOL)animated;
- (int) number;
@end

@interface MuDocumentController : UIViewController <UIScrollViewDelegate, UIGestureRecognizerDelegate>
{
	pdf_xref *xref;
	NSString *key;
	NSMutableSet *visiblePages;
	NSMutableSet *recycledPages;
	MuOutlineController *outline;
	UIScrollView *canvas;
	UILabel *indicator;
	UISlider *slider;
	UIBarButtonItem *wrapper; // for slider
	int width; // current screen size
	int height;
	int current; // currently visible page
	int scroll_animating; // stop view updates during scrolling animations
}
- (id) initWithFile: (NSString*)filename;
- (void) createPageView: (int)number;
- (void) gotoPage: (int)number animated: (BOOL)animated;
- (void) onShowOutline: (id)sender;
- (void) onSlide: (id)sender;
- (void) onTap: (UITapGestureRecognizer*)sender;
- (void) showNavigationBar;
- (void) hideNavigationBar;
@end

@interface MuAppDelegate : NSObject <UIApplicationDelegate, UINavigationControllerDelegate>
{
	UIWindow *window;
	UINavigationController *navigator;
	MuLibraryController *library;
}
@end

#pragma mark -

static void showAlert(NSString *msg)
{
	char msgbuf[160 * 30];
	int i;

	fz_strlcpy(msgbuf, "", sizeof msgbuf);
	for (i = 0; i < fz_get_error_count(); i++)
	{
		char *s = fz_get_error_line(i);
		s = strstr(s, "(): ") + 4;
		fz_strlcat(msgbuf, s, sizeof msgbuf);
		fz_strlcat(msgbuf, "\n", sizeof msgbuf);
	}

	UIAlertView *alert = [[UIAlertView alloc]
		initWithTitle: msg
		message: [NSString stringWithUTF8String: msgbuf]
		delegate: nil
		cancelButtonTitle: @"Okay"
		otherButtonTitles: nil];
	[alert show];
	[alert release];
}

static int pageNumberFromLink(pdf_xref *xref, pdf_link *link)
{
	if (link->kind == PDF_LINK_GOTO)
		return pdf_find_page_number(xref, fz_array_get(link->dest, 0));
	return -1;
}

static void loadOutlineImp(NSMutableArray *titles, NSMutableArray *pages, pdf_xref *xref, pdf_outline *outline, int level)
{
	char buf[512];
	memset(buf, 0, sizeof buf);
	memset(buf, ' ', level * 4);
	while (outline)
	{
		int number = pageNumberFromLink(xref, outline->link);
		if (number >= 0) {
			[titles addObject: [NSString stringWithFormat: @"%s%s", buf, outline->title]];
			[pages addObject: [NSNumber numberWithInt: number]];
		}
		loadOutlineImp(titles, pages, xref, outline->child, level + 1);
		outline = outline->next;
	}
}

static void loadOutline(NSMutableArray *titles, NSMutableArray *pages, pdf_xref *xref)
{
	pdf_outline *outline = pdf_load_outline(xref);
	if (outline) {
		loadOutlineImp(titles, pages, xref, outline, 0);
		pdf_free_outline(outline);
	}
}

static void releasePixmap(void *info, const void *data, size_t size)
{
	fz_drop_pixmap(info);
}

static UIImage *newImageWithPixmap(fz_pixmap *pix)
{
	CGDataProviderRef cgdata = CGDataProviderCreateWithData(pix, pix->samples, pix->w * 4 * pix->h, releasePixmap);
	CGImageRef cgimage = CGImageCreate(pix->w, pix->h, 8, 32, 4 * pix->w,
			CGColorSpaceCreateDeviceRGB(),
			kCGBitmapByteOrderDefault,
			cgdata, NULL, NO, kCGRenderingIntentDefault);
	UIImage *image = [[UIImage alloc] initWithCGImage: cgimage];
	CGDataProviderRelease(cgdata);
	CGImageRelease(cgimage);
	return image;
}

static CGSize fitPageToScreen(CGSize page, CGSize screen)
{
	float hscale = screen.width / page.width;
	float vscale = screen.height / page.height;
	float scale = MIN(hscale, vscale);
	hscale = floorf(page.width * scale) / page.width;
	vscale = floorf(page.height * scale) / page.height;
	return CGSizeMake(hscale, vscale);
}

static UIImage *renderPage(pdf_xref *xref, int number, CGSize screen)
{
	fz_error error;
	CGSize pagesize;
	fz_rect mediabox;
	fz_bbox bbox;
	fz_matrix ctm;
	fz_device *dev;
	fz_pixmap *pix;
	pdf_page *page;
	CGSize scale;

	error = pdf_load_page(&page, xref, number);
	if (error) {
		showAlert(@"Cannot load page");
		return nil;
	}

	mediabox = fz_transform_rect(fz_rotate(page->rotate), page->mediabox);
	pagesize = CGSizeMake(mediabox.x1 - mediabox.x0, mediabox.y1 - mediabox.y0);
	scale = fitPageToScreen(pagesize, screen);

	ctm = fz_concat(fz_scale(scale.width, -scale.height), fz_rotate(page->rotate));
	mediabox = fz_transform_rect(ctm, page->mediabox);
	ctm = fz_concat(ctm, fz_translate(-mediabox.x0, -mediabox.y0));
	bbox = fz_round_rect(fz_transform_rect(ctm, page->mediabox));

	pix = fz_new_pixmap_with_rect(fz_device_rgb, bbox);
	fz_clear_pixmap_with_color(pix, 255);

	dev = fz_new_draw_device(glyphcache, pix);
	pdf_run_page(xref, page, dev, ctm);
	fz_free_device(dev);

	pdf_free_page(page);
	pdf_age_store(xref->store, 3);
	fz_flush_warnings();

	return newImageWithPixmap(pix);
}

static UIImage *renderTile(pdf_xref *xref, int number, CGSize screen, CGRect tile, float zoom)
{
	fz_error error;
	CGSize pagesize;
	fz_rect mediabox;
	fz_rect tilebox;
	fz_bbox bbox;
	fz_matrix ctm;
	fz_device *dev;
	fz_pixmap *pix;
	pdf_page *page;
	CGSize scale;

	error = pdf_load_page(&page, xref, number);
	if (error) {
		showAlert(@"Cannot load page");
		return nil;
	}

	mediabox = fz_transform_rect(fz_rotate(page->rotate), page->mediabox);
	pagesize = CGSizeMake(mediabox.x1 - mediabox.x0, mediabox.y1 - mediabox.y0);
	scale = fitPageToScreen(pagesize, screen);
	scale.width *= zoom;
	scale.height *= zoom;

	ctm = fz_concat(fz_scale(scale.width, -scale.height), fz_rotate(page->rotate));
	mediabox = fz_transform_rect(ctm, page->mediabox);
	ctm = fz_concat(ctm, fz_translate(-mediabox.x0, -mediabox.y0));
	bbox = fz_round_rect(fz_transform_rect(ctm, page->mediabox));

	tilebox.x0 = tile.origin.x + bbox.x0;
	tilebox.y0 = tile.origin.y + bbox.y0;
	tilebox.x1 = tilebox.x0 + tile.size.width;
	tilebox.y1 = tilebox.y0 + tile.size.height;
	bbox = fz_round_rect(tilebox);
printf("render tile %d %d %d %d\n", bbox.x0, bbox.y0, bbox.x1, bbox.y1);

	pix = fz_new_pixmap_with_rect(fz_device_rgb, bbox);
	fz_clear_pixmap_with_color(pix, 255);

	dev = fz_new_draw_device(glyphcache, pix);
	pdf_run_page(xref, page, dev, ctm);
	fz_free_device(dev);

	pdf_free_page(page);
	pdf_age_store(xref->store, 3);
	fz_flush_warnings();

	return newImageWithPixmap(pix);
}

#pragma mark -

@implementation MuLibraryController

- (void) viewWillAppear: (BOOL)animated
{
	[self setTitle: @"PDF and XPS Documents"];
	[self reload];
	printf("library viewWillAppear (starting reload timer)\n");
	timer = [NSTimer timerWithTimeInterval: 1
		target: self selector: @selector(reload) userInfo: nil
		repeats: YES];
	[[NSRunLoop currentRunLoop] addTimer: timer forMode: NSDefaultRunLoopMode];
}

- (void) viewWillDisappear: (BOOL)animated
{
	printf("library viewWillDisappear (stopping reload timer)\n");
	[timer invalidate];
	timer = nil;
}

- (void) reload
{
	NSError *error = nil;

	if (files) {
		[files release];
		files = nil;
	}

	NSString *docdir = [NSString stringWithFormat: @"%@/Documents", NSHomeDirectory()];
	files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath: docdir error: &error];
	if (error)
		files = [NSArray arrayWithObjects: @"...error loading directory...", nil];
	[files retain];

	[[self tableView] reloadData];
}

- (void) dealloc
{
	[files release];
	[super dealloc];
}

- (BOOL) shouldAutorotateToInterfaceOrientation: (UIInterfaceOrientation)o
{
	return YES;
}

- (NSInteger) numberOfSectionsInTableView: (UITableView*)tableView
{
	return 1;
}

- (NSInteger) tableView: (UITableView*)tableView numberOfRowsInSection: (NSInteger)section
{
	return [files count] + 1;
}

- (UITableViewCell*) tableView: (UITableView*)tableView cellForRowAtIndexPath: (NSIndexPath*)indexPath
{
	static NSString *cellid = @"MuCellIdent";
	UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier: cellid];
	if (!cell)
		cell = [[[UITableViewCell alloc] initWithStyle: UITableViewCellStyleDefault reuseIdentifier: cellid] autorelease];
	int row = [indexPath row];
	if (row == 0) {
		[[cell textLabel] setText: @"About MuPDF"];
		[[cell textLabel] setFont: [UIFont italicSystemFontOfSize: 20]];
	} else {
		[[cell textLabel] setText: [files objectAtIndex: row - 1]];
		[[cell textLabel] setFont: [UIFont systemFontOfSize: 21]];
	}
	return cell;
}

- (void) tableView: (UITableView*)tableView didSelectRowAtIndexPath: (NSIndexPath*)indexPath
{
	int row = [indexPath row];
	if (row == 0)
		[self openDocument: @"../MuPDF.app/About.pdf"];
	else
		[self openDocument: [files objectAtIndex: row - 1]];
}

- (void) openDocument: (NSString*)filename
{
	MuDocumentController *document = [[MuDocumentController alloc] initWithFile: filename];
	if (document) {
		[self setTitle: @"Library"];
		[[self navigationController] pushViewController: document animated: YES];
		[document release];
	}
}

@end

#pragma mark -

@implementation MuOutlineController

- (id) initWithTarget: (id)aTarget titles: (NSMutableArray*)aTitles pages: (NSMutableArray*)aPages
{
	self = [super initWithStyle: UITableViewStylePlain];
	if (self) {
		[self setTitle: @"Table of Contents"];
		target = aTarget; // only keep a weak reference, to avoid retain cycles
		titles = [aTitles retain];
		pages = [aPages retain];
		[[self tableView] setSeparatorStyle: UITableViewCellSeparatorStyleNone];
	}
	return self;
}

- (void) dealloc
{
	[titles release];
	[pages release];
	[super dealloc];
}

- (BOOL) shouldAutorotateToInterfaceOrientation: (UIInterfaceOrientation)o
{
	return YES;
}

- (NSInteger) numberOfSectionsInTableView: (UITableView*)tableView
{
	return 1;
}

- (NSInteger) tableView: (UITableView*)tableView numberOfRowsInSection: (NSInteger)section
{
	return [titles count];
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath
{
	return 28;
}

- (UITableViewCell*) tableView: (UITableView*)tableView cellForRowAtIndexPath: (NSIndexPath*)indexPath
{
	static NSString *cellid = @"MuCellIdent";
	UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier: cellid];
	if (!cell)
		cell = [[[UITableViewCell alloc] initWithStyle: UITableViewCellStyleValue1 reuseIdentifier: cellid] autorelease];
	NSString *title = [titles objectAtIndex: [indexPath row]];
	NSString *page = [pages objectAtIndex: [indexPath row]];
	[[cell textLabel] setFont: [UIFont systemFontOfSize: 16]];
	[[cell detailTextLabel] setFont: [UIFont systemFontOfSize: 16]];
	[[cell textLabel] setText: title];
	[[cell detailTextLabel] setText: [NSString stringWithFormat: @"%d", [page intValue]+1]];
	return cell;
}

- (void) tableView: (UITableView*)tableView didSelectRowAtIndexPath: (NSIndexPath*)indexPath
{
	NSNumber *page = [pages objectAtIndex: [indexPath row]];
	[target gotoPage: [page intValue] animated: NO];
	[[self navigationController] popViewControllerAnimated: YES];
}

@end

#pragma mark -

@implementation MuPageView

- (id) initWithFrame: (CGRect)frame xref: (pdf_xref*)aXref page: (int)aNumber
{
	self = [super initWithFrame: frame];
	if (self) {
		xref = aXref;
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
	if (number < 0 || number >= pdf_count_pages(xref))
		return;
	dispatch_async(queue, ^{
		if (!cancel) {
			printf("loading page %d\n", number);
			UIImage *image = renderPage(xref, number, self.bounds.size);
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

	if (!imageView) {
		imageView = [[UIImageView alloc] initWithImage: image];
		[self addSubview: imageView];
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
					if (fabs(scale.width - 1) > 0.1)
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
}

- (UIView*) viewForZoomingInScrollView: (UIScrollView*)scrollView
{
	return imageView;
}

- (void) loadTile
{
	CGSize pageSize = self.bounds.size;

	tileFrame.origin = self.contentOffset;
	tileFrame.size = self.bounds.size;
	tileFrame = CGRectIntersection(tileFrame, imageView.frame);
	tileScale = self.zoomScale;

	CGRect frame = tileFrame;
	float scale = tileScale;

	CGRect viewFrame = frame;
	if (self.contentOffset.x < imageView.frame.origin.x)
		viewFrame.origin.x = 0;
	if (self.contentOffset.y < imageView.frame.origin.y)
		viewFrame.origin.y = 0;

	if (scale < 1.1)
		return;

	printf("queuing tile\n");

	dispatch_async(queue, ^{
		__block BOOL isValid;
		dispatch_sync(dispatch_get_main_queue(), ^{
			isValid = CGRectEqualToRect(frame, tileFrame) && scale == tileScale;
		});
		if (!isValid) {
			puts("cancel tile");
			return;
		}

		UIImage *image = renderTile(xref, number, pageSize, viewFrame, scale);

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

@end

#pragma mark -

@implementation MuDocumentController

- (id) initWithFile: (NSString*)nsfilename
{
	fz_error error;
	char filename[PATH_MAX];
	char *password = "";

	self = [super init];
	if (!self)
		return nil;

	key = [nsfilename retain];

	dispatch_sync(queue, ^{});

	strcpy(filename, [NSHomeDirectory() UTF8String]);
	strcat(filename, "/Documents/");
	strcat(filename, [nsfilename UTF8String]);

	printf("open xref '%s'\n", filename);

	error = pdf_open_xref(&xref, filename, password);
	if (error) {
		showAlert(@"Cannot open PDF file");
		[self release];
		return nil;
	}

	error = pdf_load_page_tree(xref);
	if (error) {
		showAlert(@"Cannot open document");
		[self release];
		return nil;
	}

	NSMutableArray *titles = [[NSMutableArray alloc] init];
	NSMutableArray *pages = [[NSMutableArray alloc] init];
	loadOutline(titles, pages, xref);
	if ([titles count]) {
		outline = [[MuOutlineController alloc] initWithTarget: self titles: titles pages: pages];
		[[self navigationItem] setRightBarButtonItem:
			[[UIBarButtonItem alloc]
				initWithBarButtonSystemItem: UIBarButtonSystemItemBookmarks
				target:self action:@selector(onShowOutline:)]];
	}
	[titles release];
	[pages release];

	return self;
}

- (void) loadView
{
	[[NSUserDefaults standardUserDefaults] setObject: key forKey: @"OpenDocumentKey"];

	current = [[NSUserDefaults standardUserDefaults] integerForKey: key];
	if (current < 0 || current >= pdf_count_pages(xref))
		current = 0;

	UIView *view = [[UIView alloc] initWithFrame: CGRectZero];
	[view setAutoresizingMask: UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
	[view setAutoresizesSubviews: YES];

	visiblePages = [[NSMutableSet alloc] init];
	recycledPages = [[NSMutableSet alloc] init];

	canvas = [[UIScrollView alloc] initWithFrame: CGRectMake(0,0,GAP,0)];
	[canvas setAutoresizingMask: UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
	[canvas setPagingEnabled: YES];
	[canvas setShowsHorizontalScrollIndicator: NO];
	[canvas setShowsVerticalScrollIndicator: NO];
	[canvas setDelegate: self];

	[canvas addGestureRecognizer: [[[UITapGestureRecognizer alloc] initWithTarget: self action: @selector(onTap:)] autorelease]];

	scroll_animating = NO;

	indicator = [[UILabel alloc] initWithFrame: CGRectZero];
	[indicator setAutoresizingMask: UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleTopMargin];
	[indicator setText: @"0000 of 9999"];
	[indicator sizeToFit];
	[indicator setCenter: CGPointMake(0, INDICATOR_Y)];
	[indicator setTextAlignment: UITextAlignmentCenter];
	[indicator setBackgroundColor: [[UIColor blackColor] colorWithAlphaComponent: 0.5]];
	[indicator setTextColor: [UIColor whiteColor]];

	slider = [[UISlider alloc] initWithFrame: CGRectZero];
	[slider setMinimumValue: 0];
	[slider setMaximumValue: pdf_count_pages(xref) - 1];
	[slider addTarget: self action: @selector(onSlide:) forControlEvents: UIControlEventValueChanged];

	[view addSubview: canvas];
	[view addSubview: indicator];

	wrapper = [[UIBarButtonItem alloc] initWithCustomView: slider];
	[self setToolbarItems: [NSArray arrayWithObjects: wrapper, nil]];

	[self setView: view];
	[view release];
}

- (void) viewDidUnload
{
	[visiblePages release]; visiblePages = nil;
	[recycledPages release]; recycledPages = nil;
	[indicator release]; indicator = nil;
	[slider release]; slider = nil;
	[wrapper release]; wrapper = nil;
	[canvas release]; canvas = nil;
}

- (void) dealloc
{
	if (xref) {
		pdf_xref *self_xref = xref; // don't auto-retain self here!
		dispatch_async(queue, ^{
			printf("close xref\n");
			pdf_free_xref(self_xref);
		});
	}
	[outline release];
	[key release];
	[super dealloc];
}

- (void) viewWillAppear: (BOOL)animated
{
	CGSize size = [canvas frame].size;
	width = size.width;
	height = size.height;

	[self setTitle: [key lastPathComponent]];

	[slider setValue: current];

	[indicator setText: [NSString stringWithFormat: @" %d of %d ", current+1, pdf_count_pages(xref)]];

	[canvas setContentInset: UIEdgeInsetsZero];
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];

	[wrapper setWidth: width - GAP - 24];

	[[self navigationController] setToolbarHidden: NO animated: animated];
}

- (void) viewDidAppear: (BOOL)animated
{
	[self scrollViewDidScroll: canvas];
}

- (void) viewWillDisappear: (BOOL)animated
{
	[self setTitle: @"Resume"];
	[[NSUserDefaults standardUserDefaults] removeObjectForKey: @"OpenDocumentKey"];
	[[self navigationController] setToolbarHidden: YES animated: animated];
}

- (void) showNavigationBar
{
	if ([[self navigationController] isNavigationBarHidden]) {
		[[self navigationController] setNavigationBarHidden: NO];
		[[self navigationController] setToolbarHidden: NO];
		[indicator setHidden: NO];

		[UIView beginAnimations: @"MuNavBar" context: NULL];

		[[[self navigationController] navigationBar] setAlpha: 1];
		[[[self navigationController] toolbar] setAlpha: 1];
		[indicator setAlpha: 1];

		[UIView commitAnimations];
	}
}

- (void) hideNavigationBar
{
	if (![[self navigationController] isNavigationBarHidden]) {
		[UIView beginAnimations: @"MuNavBar" context: NULL];
		[UIView setAnimationDelegate: self];
		[UIView setAnimationDidStopSelector: @selector(onHideNavigationBarFinished)];

		[[[self navigationController] navigationBar] setAlpha: 0];
		[[[self navigationController] toolbar] setAlpha: 0];
		[indicator setAlpha: 0];

		[UIView commitAnimations];
	}
}

- (void) onHideNavigationBarFinished
{
	[[self navigationController] setNavigationBarHidden: YES];
	[[self navigationController] setToolbarHidden: YES];
	[indicator setHidden: YES];
}

- (void) onShowOutline: (id)sender
{
	[[self navigationController] pushViewController: outline animated: YES];
}

- (void) onSlide: (id)sender
{
	int number = [slider value];
	if ([slider isTracking])
		[indicator setText: [NSString stringWithFormat: @" %d of %d ", number+1, pdf_count_pages(xref)]];
	else
		[self gotoPage: number animated: NO];
}

- (void) onTap: (UITapGestureRecognizer*)sender
{
	CGPoint p = [sender locationInView: canvas];
	CGPoint ofs = [canvas contentOffset];
	float x0 = (width - GAP) / 5;
	float x1 = (width - GAP) - x0;
	p.x -= ofs.x;
	p.y -= ofs.y;
	if (p.x < x0) {
		[self gotoPage: current-1 animated: YES];
	} else if (p.x > x1) {
		[self gotoPage: current+1 animated: YES];
	} else {
		if ([[self navigationController] isNavigationBarHidden])
			[self showNavigationBar];
		else
			[self hideNavigationBar];
	}
}

- (void) scrollViewWillBeginDragging: (UIScrollView *)scrollView
{
	[self hideNavigationBar];
}

- (void) scrollViewDidScroll: (UIScrollView*)scrollview
{
	if (width == 0)
		return; // not visible yet

	if (scroll_animating)
		return; // don't mess with layout during animations

	float x = [canvas contentOffset].x + width * 0.5f;
	current = x / width;

	[[NSUserDefaults standardUserDefaults] setInteger: current forKey: key];

	[indicator setText: [NSString stringWithFormat: @" %d of %d ", current+1, pdf_count_pages(xref)]];
	[slider setValue: current];

	// swap the page views in and out

	for (MuPageView *view in visiblePages) {
		if ([view number] != current)
			[view resetZoomAnimated: YES];
		if ([view number] < current - 1 || [view number] > current + 1) {
			[recycledPages addObject: view];
			[view removeFromSuperview];
		}
	}
	[visiblePages minusSet: recycledPages];
	[recycledPages removeAllObjects]; // don't bother recycling them...

	[self createPageView: current];
	[self createPageView: current - 1];
	[self createPageView: current + 1];
}

- (void) createPageView: (int)number
{
	if (number < 0 || number >= pdf_count_pages(xref))
		return;
	int found = 0;
	for (MuPageView *view in [canvas subviews])
		if ([view number] == number)
			found = 1;
	if (!found) {
		MuPageView *view = [[MuPageView alloc] initWithFrame: CGRectMake(number * width, 0, width-GAP, height) xref: xref page: number];
		[visiblePages addObject: view];
		[canvas addSubview: view];
		[view release];
	}
}

- (void) gotoPage: (int)number animated: (BOOL)animated
{
	if (number < 0)
		number = 0;
	if (number >= pdf_count_pages(xref))
		number = pdf_count_pages(xref) - 1;
	if (animated) {
		// setContentOffset:animated: does not use the normal animation
		// framework. It also doesn't play nice with the tap gesture
		// recognizer. So we do our own page flipping animation here.
		// We must set the scroll_animating flag so that we don't create
		// or remove subviews until after the animation, or they'll
		// swoop in from origo during the animation.

		scroll_animating = YES;
		[UIView beginAnimations: @"MuScroll" context: NULL];
		[UIView setAnimationDuration: 0.4];
		[UIView setAnimationBeginsFromCurrentState: YES];
		[UIView setAnimationDelegate: self];
		[UIView setAnimationDidStopSelector: @selector(onGotoPageFinished)];

		for (MuPageView *view in visiblePages)
			[view resetZoomAnimated: NO];

		[canvas setContentOffset: CGPointMake(number * width, 0)];
		[slider setValue: number];
		[indicator setText: [NSString stringWithFormat: @" %d of %d ", number+1, pdf_count_pages(xref)]];

		[UIView commitAnimations];
	} else {
		for (MuPageView *view in visiblePages)
			[view resetZoomAnimated: NO];
		[canvas setContentOffset: CGPointMake(number * width, 0)];
	}
	current = number;
}

- (void) onGotoPageFinished
{
	scroll_animating = NO;
	[self scrollViewDidScroll: canvas];
}

- (BOOL) shouldAutorotateToInterfaceOrientation: (UIInterfaceOrientation)o
{
	return YES;
}

- (void) willAnimateRotationToInterfaceOrientation: (UIInterfaceOrientation)interfaceOrientation duration:(NSTimeInterval)duration
{
	CGSize size = [canvas frame].size;
	int max_width = MAX(width, size.width);

	width = size.width;
	height = size.height;

	[wrapper setWidth: width - GAP - 24];
	[[[self navigationController] toolbar] setNeedsLayout]; // force layout!

	// use max_width so we don't clamp the content offset too early during animation
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * max_width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];

	for (MuPageView *view in visiblePages) {
		if ([view number] == current) {
			[view setFrame: CGRectMake([view number] * width, 0, width-GAP, height)];
			[view willRotate];
		}
	}
	for (MuPageView *view in visiblePages) {
		if ([view number] != current) {
			[view setFrame: CGRectMake([view number] * width, 0, width-GAP, height)];
			[view willRotate];
		}
	}
}

- (void) didRotateFromInterfaceOrientation: (UIInterfaceOrientation)o
{
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];
}

@end

#pragma mark -

@implementation MuAppDelegate

- (BOOL) application: (UIApplication*)application didFinishLaunchingWithOptions: (NSDictionary*)launchOptions
{
	queue = dispatch_queue_create("com.artifex.mupdf.queue", NULL);

	glyphcache = fz_new_glyph_cache();

	library = [[MuLibraryController alloc] initWithStyle: UITableViewStylePlain];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];
	[[navigator navigationBar] setTranslucent: YES];
	[[navigator toolbar] setTranslucent: YES];
	[navigator setDelegate: self];

	window = [[UIWindow alloc] initWithFrame: [[UIScreen mainScreen] bounds]];
	[window setBackgroundColor: [UIColor scrollViewTexturedBackgroundColor]];
	[window addSubview: [navigator view]];
	[window makeKeyAndVisible];

	NSString *filename = [[NSUserDefaults standardUserDefaults] objectForKey: @"OpenDocumentKey"];
	if (filename)
		[library openDocument: filename];

	return YES;
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
	printf("applicationDidEnterBackground!\n");
	[[NSUserDefaults standardUserDefaults] synchronize];
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
	printf("applicationWillEnterForeground!\n");
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
	printf("applicationDidBecomeActive!\n");
}

- (void)applicationWillTerminate:(UIApplication *)application
{
	printf("applicationWillTerminate!\n");
	[[NSUserDefaults standardUserDefaults] synchronize];
}

- (void)applicationDidReceiveMemoryWarning:(UIApplication *)application
{
	printf("applicationDidReceiveMemoryWarning\n");
}

- (void) dealloc
{
	dispatch_release(queue);
	[library release];
	[navigator release];
	[window release];
	[super dealloc];
}

@end

#pragma mark -

int main(int argc, char *argv[])
{
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	int retVal = UIApplicationMain(argc, argv, nil, @"MuAppDelegate");
	[pool release];
	return retVal;
}
