#import <UIKit/UIKit.h>

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
	UIImageView *imageView;
	UIActivityIndicatorView *loadingView;
	pdf_xref *xref;
	int number;
	int cancel;
}
- (id) initWithFrame: (CGRect)frame xref: (pdf_xref*)aXref page: (int)aNumber;
- (void) displayImage: (UIImage*)image;
- (void) loadPage;
- (void) onRotate;
- (void) resetZoom;
- (void) resetZoomAnimated;
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
- (void) layoutPageViews;
- (void) rotatePageViews;
- (void) createPageView: (int)number;
- (void) gotoPage: (int)number animated: (BOOL)animated;
- (void) onTap: (UITapGestureRecognizer*)sender;
- (void) onSlide: (id)sender;
- (void) showOutline: (id)sender;
- (void) hideNavigationBar;
- (void) showNavigationBar;
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

	ctm = fz_translate(0, -page->mediabox.y1);
	ctm = fz_concat(ctm, fz_scale(scale.width, -scale.height));
	ctm = fz_concat(ctm, fz_rotate(page->rotate));
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
	[self setTitle: @"Library"];
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

		[self setShowsVerticalScrollIndicator: NO];
		[self setShowsHorizontalScrollIndicator: NO];
		[self setDecelerationRate: UIScrollViewDecelerationRateFast];
		[self setDelegate: self];

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
	printf("pageview dealloc (%d)\n", number);
	[loadingView release];
	[imageView release];
	[super dealloc];
}

- (int) number
{
	return number;
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
	cancel = NO;
	dispatch_async(queue, ^{
		if (!cancel) {
			printf("loading page %d\n", number);
			UIImage *image = renderPage(xref, number, [self bounds].size);
			dispatch_async(dispatch_get_main_queue(), ^{
				[self displayImage: image];
				[image release];
			});
		} else {
			printf("cancel page %d\n", number);
		}
	});
}

- (void) resetZoomAnimated: (BOOL)animated
{
	[self setMinimumZoomScale: 1];
	[self setMaximumZoomScale: 3];
	[self setZoomScale: 1 animated: animated];
}

- (void) displayImage: (UIImage*)image
{
	[loadingView removeFromSuperview];
	[loadingView release];
	loadingView = nil;

	[imageView removeFromSuperview];
	[imageView release];
	imageView = nil;

	// TODO: if rotated during loading the size won't be as expected
	// TODO: ... and what to do about zooming ...
	// TODO: [[UIScreen mainScreen] scale]; -- for retina iphone 4 displays we want double resolution!

	[self resetZoomAnimated: NO];

	imageView = [[UIImageView alloc] initWithImage: image];
	[self addSubview: imageView];
	[self setContentSize: [imageView frame].size];
}

- (void) onRotate
{
	[self resetZoomAnimated: NO];

	CGSize imageSize = [[imageView image] size];
	CGSize scale = fitPageToScreen(imageSize, [self bounds].size);
	if (fabs(scale.width - 1) > 0.1) {
printf("image size is off, reloading (%d)\n", number);
		[self loadPage];
		CGRect frame = [imageView frame];
		frame.size.width = imageSize.width * scale.width;
		frame.size.height = imageSize.height * scale.height;
		[imageView setFrame: frame];
	} else {
		[imageView sizeToFit];
	}

	[self setContentSize: [imageView frame].size];

	[self setNeedsLayout];
	[self layoutIfNeeded];
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
				target:self action:@selector(showOutline:)]];
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
	[self layoutPageViews];
}

- (void) viewWillDisappear: (BOOL)animated
{
	[self setTitle: @"Resume"];
	[[NSUserDefaults standardUserDefaults] removeObjectForKey: @"OpenDocumentKey"];
	[[self navigationController] setToolbarHidden: YES animated: animated];
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
		printf("close xref\n");
		pdf_free_xref(xref);
	}
	[outline release];
	[key release];
	[super dealloc];
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

- (void) onSlide: (id)sender
{
	int number = [slider value];
	if ([slider isTracking])
		[indicator setText: [NSString stringWithFormat: @" %d of %d ", number+1, pdf_count_pages(xref)]];
	else
		[self gotoPage: number animated: NO];
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

	[self layoutPageViews];

	[indicator setText: [NSString stringWithFormat: @" %d of %d ", current+1, pdf_count_pages(xref)]];
	[slider setValue: current];
}

- (void) layoutPageViews
{
	for (MuPageView *view in visiblePages) {
		if ([view number] != current)
			[view resetZoomAnimated: YES];
		if ([view number] < current - 2 || [view number] > current + 2) {
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

- (void) rotatePageViews
{
	for (MuPageView *view in visiblePages)
		[view setFrame: CGRectMake([view number] * width, 0, width-GAP, height)];
	for (MuPageView *view in visiblePages)
		if ([view number] == current)
			[view onRotate];
	for (MuPageView *view in visiblePages)
		if ([view number] != current)
			[view onRotate];
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

	[self rotatePageViews];
}

- (void) didRotateFromInterfaceOrientation: (UIInterfaceOrientation)o
{
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];
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

- (void) showOutline: (id)sender
{
	[[self navigationController] pushViewController: outline animated: YES];
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
