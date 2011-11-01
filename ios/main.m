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
static UIImage *loadingImage = nil;
static UIBarButtonItem *flexibleSpace = nil;
static NSString *docdir = nil;

@interface MuLibraryController : UITableViewController
{
	NSArray *files;
}
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

@interface MuDocumentController : UIViewController <UIScrollViewDelegate>
{
	pdf_xref *xref;
	MuOutlineController *outline;
	UIScrollView *canvas;
	UILabel *indicator;
	UISlider *slider;
	UIBarButtonItem *wrapper; // for slider
	UIImageView **pageviews;
	int width; // current screen size
	int height;
	int current; // currently visible page
	int scroll_animating; // stop view updates during scrolling animations
}
- (id) initWithFile: (NSString*)filename;
- (void) loadPage: (int)number;
- (void) reloadPage: (int)number;
- (void) unloadPage: (int)number;
- (void) layoutPage: (int)number;
- (void) gotoPage: (int)number animated: (BOOL)animated;
- (void) didSingleTap: (UITapGestureRecognizer*)sender;
- (void) didSlide: (id)sender;
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
		int number =  pageNumberFromLink(xref, outline->link);
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

static UIImage *renderPage(pdf_xref *xref, int number, float width, float height)
{
	fz_bbox bbox;
	fz_matrix ctm;
	fz_device *dev;
	fz_pixmap *pix;
	pdf_page *page;
	fz_error error;
	float scale, hscale, vscale;

	printf("loading page %d [%g %g]\n", number, width, height);

	error = pdf_load_page(&page, xref, number);
	if (error) {
		showAlert(@"Cannot load page");
		return nil;
	}

	hscale = width / (page->mediabox.x1 - page->mediabox.x0);
	vscale = height / (page->mediabox.y1 - page->mediabox.y0);
	scale = MIN(hscale, vscale);

	ctm = fz_translate(0, -page->mediabox.y1);
	ctm = fz_concat(ctm, fz_scale(scale, -scale));
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

- (void) reload
{
	[self setTitle: @"MuPDF"];

	NSError *error = nil;

	if (files) {
		[files release];
		files = nil;
	}

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
	} else {
		[[cell textLabel] setText: [files objectAtIndex: row - 1]];
	}
	[[cell textLabel] setFont: [UIFont boldSystemFontOfSize: 20]];
//	[[cell textLabel] setBackgroundColor: [UIColor clearColor]];
//	[[cell contentView] setBackgroundColor: row & 1 ?
//		[UIColor colorWithWhite: 1.0 alpha: 1] :
//		[UIColor colorWithWhite: 0.9 alpha: 1]];
	return cell;
}

- (void) tableView: (UITableView*)tableView didSelectRowAtIndexPath: (NSIndexPath*)indexPath
{
	int row = [indexPath row];
	NSString *filename;
	if (row == 0)
		filename = @"../MuPDF.app/About.pdf";
	else
		filename = [files objectAtIndex: row - 1];
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
		target = [aTarget retain];
		titles = [aTitles retain];
		pages = [aPages retain];
	}
	return self;
}

- (void) dealloc
{
	[target release];
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

@implementation MuDocumentController

- (id) initWithFile: (NSString*)nsfilename
{
	fz_error error;
	char filename[PATH_MAX];
	char *password = "";

	self = [super init];
	if (!self)
		return nil;

	dispatch_sync(queue, ^{});

	strcpy(filename, [docdir UTF8String]);
	strcat(filename, "/");
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

	[self setTitle: [nsfilename lastPathComponent]];

	NSMutableArray *titles = [[NSMutableArray alloc] init];
	NSMutableArray *pages = [[NSMutableArray alloc] init];
	loadOutline(titles, pages, xref);
	if ([titles count]) {
		outline = [[MuOutlineController alloc] initWithTarget: self titles: titles pages: pages];
		[[outline tableView] setSeparatorStyle: UITableViewCellSeparatorStyleNone];
		[[self navigationItem] setRightBarButtonItem:
			[[UIBarButtonItem alloc]
				initWithBarButtonSystemItem: UIBarButtonSystemItemBookmarks
				target:self action:@selector(showOutline:)]];
	}
	[titles release];
	[pages release];

	pageviews = calloc(pdf_count_pages(xref), sizeof *pageviews);

	return self;
}

- (void) loadView
{
	UIView *view = [[UIView alloc] initWithFrame: CGRectZero];
	[view setAutoresizingMask: UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
	[view setAutoresizesSubviews: YES];

	canvas = [[UIScrollView alloc] initWithFrame: CGRectMake(0,0,GAP,0)];
	[canvas setAutoresizingMask: UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
	[canvas setPagingEnabled: YES];
	[canvas setShowsHorizontalScrollIndicator: NO];
	[canvas setShowsVerticalScrollIndicator: NO];
	[canvas setDelegate: self];

	[canvas addGestureRecognizer: [[UITapGestureRecognizer alloc] initWithTarget: self action: @selector(didSingleTap:)]];

	scroll_animating = NO;

	indicator = [[UILabel alloc] initWithFrame: CGRectZero];
	[indicator setAutoresizingMask: UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleTopMargin];
	[indicator setText: @"0000 of 9999"];
	[indicator sizeToFit];
	[indicator setText: [NSString stringWithFormat: @" %d of %d ", current+1, pdf_count_pages(xref)]];
	[indicator setCenter: CGPointMake(0, INDICATOR_Y)];
	[indicator setTextAlignment: UITextAlignmentCenter];
	[indicator setBackgroundColor: [[UIColor blackColor] colorWithAlphaComponent: 0.5]];
	[indicator setTextColor: [UIColor whiteColor]];

	slider = [[UISlider alloc] initWithFrame: CGRectZero];
	[slider setMinimumValue: 0];
	[slider setMaximumValue: pdf_count_pages(xref) - 1];
	[slider setValue: current];
	[slider addTarget: self action: @selector(didSlide:) forControlEvents: UIControlEventValueChanged];

	[view addSubview: canvas];
	[view addSubview: indicator];

	wrapper = [[UIBarButtonItem alloc] initWithCustomView: slider];
	[self setToolbarItems: [NSArray arrayWithObjects: wrapper, nil]];

	[self setView: view];
}

- (void) viewWillAppear: (BOOL)animated
{
	CGSize size = [canvas frame].size;
	width = size.width;
	height = size.height;

	[canvas setContentInset: UIEdgeInsetsZero];
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width - GAP, height)];
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
	[[self navigationController] setToolbarHidden: YES animated: animated];
}

- (void) dealloc
{
	if (xref)
		for (int i = 0; i < pdf_count_pages(xref); i++)
			if (pageviews[i])
				[pageviews[i] release];

	pdf_xref *self_xref = xref; // don't use self after dealloc has finished
	dispatch_async(queue, ^{
		printf("close xref\n");
		if (self_xref)
			pdf_free_xref(self_xref);
	});

	free(pageviews);

	[indicator release];
	[slider release];
	[wrapper release];
	[canvas release];
	[outline release];
	[super dealloc];
}

- (void) loadPage: (int)number
{
	if (number < 0 || number >= pdf_count_pages(xref))
		return;

	if (!pageviews[number]) {
		pageviews[number] = [[UIImageView alloc] initWithImage: loadingImage];
		[pageviews[number] setCenter: CGPointMake(number * width + width / 2, height / 2)];
		[canvas addSubview: pageviews[number]];
		[self reloadPage: number];
	}
}

- (void) unloadPage: (int)number
{
	if (number < 0 || number >= pdf_count_pages(xref))
		return;

	if (pageviews[number]) {
		[pageviews[number] removeFromSuperview];
		[pageviews[number] release];
		pageviews[number] = nil;
	}
}

- (void) reloadPage: (int)number
{
	if (number < 0 || number >= pdf_count_pages(xref))
		return;

	dispatch_async(queue, ^{
		if (pageviews[number]) {
			UIImage *image = renderPage(xref, number, width - GAP, height);
			dispatch_async(dispatch_get_main_queue(), ^{
				if (pageviews[number]) {
					[pageviews[number] setImage: image];
					[self layoutPage: number];
				}
				[image release];
			});
		} else {
			printf("not loading page %d\n", number);
		}
	});
}

- (void) layoutPage: (int)number
{
	if (pageviews[number]) {
		UIImageView *page = pageviews[number];
		UIImage *image = [page image];
		if (image != loadingImage) {
			CGRect frame = [page frame];
			CGSize pagesize = [image size];
			float scale = MIN((width - GAP) / pagesize.width, height / pagesize.height);
			if (fabs(scale - 1) > 0.1) {
				[self reloadPage: number];
				frame.size.width = pagesize.width * scale;
				frame.size.height = pagesize.height * scale;
				[page setFrame: frame];
			} else {
				[page sizeToFit];
			}
		} else {
			[page sizeToFit];
		}
		[page setCenter: CGPointMake(number * width + (width-GAP)/2, height/2)];
	}
}

- (void) hideNavigationBar
{
	if (![[self navigationController] isNavigationBarHidden]) {
		[UIView beginAnimations: @"MuNavBar" context: NULL];
		[UIView setAnimationDelegate: self];
		[UIView setAnimationDidStopSelector: @selector(didHideNavigationBar)];

		[[[self navigationController] navigationBar] setAlpha: 0];
		[[[self navigationController] toolbar] setAlpha: 0];
		[indicator setAlpha: 0];

		[UIView commitAnimations];
	}
}

- (void) didHideNavigationBar
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

- (void) didSlide: (id)sender
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

	for (int i = 0; i < pdf_count_pages(xref); i++)
		if (i < current - 2 || i > current + 2)
			[self unloadPage: i];
	[self loadPage: current];
	[self loadPage: current + 1];
	[self loadPage: current - 1];

	[indicator setText: [NSString stringWithFormat: @" %d of %d ", current+1, pdf_count_pages(xref)]];
	[slider setValue: current];
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
		[UIView setAnimationDidStopSelector: @selector(didGotoPage)];
		[canvas setContentOffset: CGPointMake(number * width, 0)];
		[slider setValue: number];
		[indicator setText: [NSString stringWithFormat: @" %d of %d ", number+1, pdf_count_pages(xref)]];
		[UIView commitAnimations];
	} else {
		[canvas setContentOffset: CGPointMake(number * width, 0)];
	}
	current = number;
}

- (void) didGotoPage
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

	[self layoutPage: current]; // make sure current page is first in queue
	for (int i = 0; i < pdf_count_pages(xref); i++)
		if (i != current)
			[self layoutPage: i];

	[wrapper setWidth: width - GAP - 24];
	[[[self navigationController] toolbar] setNeedsLayout]; // force layout!

	// use max_width so we don't clamp the content offset too early during animation
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * max_width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];
}

- (void) didRotateFromInterfaceOrientation: (UIInterfaceOrientation)o
{
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];
}

- (void) didSingleTap: (UITapGestureRecognizer*)sender
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

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	docdir = [[paths objectAtIndex: 0] retain];

	loadingImage = [[UIImage imageNamed: @"loading.png"] retain];

	flexibleSpace = [[UIBarButtonItem alloc]
		initWithBarButtonSystemItem: UIBarButtonSystemItemFlexibleSpace
		target: nil action: nil];

	library = [[MuLibraryController alloc] initWithStyle: UITableViewStylePlain];
//	[[library tableView] setSeparatorStyle: UITableViewCellSeparatorStyleNone];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];
	[[navigator navigationBar] setTranslucent: YES];
	[[navigator toolbar] setTranslucent: YES];
	[navigator setDelegate: self];

	window = [[UIWindow alloc] initWithFrame: [[UIScreen mainScreen] bounds]];
	[window setBackgroundColor: [UIColor scrollViewTexturedBackgroundColor]];
	[window addSubview: [navigator view]];
	[window makeKeyAndVisible];

	return YES;
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
	printf("applicationDidEnterBackground!\n");
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
	printf("applicationWillEnterForeground!\n");
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
	printf("applicationDidBecomeActive!\n");
	[library reload];
}

- (void)applicationWillTerminate:(UIApplication *)application
{
	printf("applicationWillTerminate!\n");
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
