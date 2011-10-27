#import <UIKit/UIKit.h>

#undef ABS
#undef MIN
#undef MAX

#include "fitz/fitz.h"
#include "pdf/mupdf.h"
#include "xps/muxps.h"

#define GAP 0

static dispatch_queue_t queue;
static fz_glyph_cache *glyphcache = NULL;
static UIImage *loadingImage = nil;

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
	UIImageView **pageviews;
	int width; // current screen size
	int height;
	int current; // currently visible page
}
- (id) initWithFile: (NSString*)filename;
- (void) loadPage: (int)number;
- (void) reloadPage: (int)number;
- (void) unloadPage: (int)number;
- (void) layoutPage: (int)number;
- (void) gotoPage: (int)number animated: (BOOL)animated;
- (void) didSingleTap: (UITapGestureRecognizer*)sender;
- (void) showOutline: (id)sender;
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

	printf("loading page %d for size %g x %g\n", number, width, height);

	error = pdf_load_page(&page, xref, number);
	if (error) {
		showAlert(@"Cannot load page");
		return nil;
	}

	hscale = width / page->mediabox.x1 - page->mediabox.x0;
	vscale = height / page->mediabox.y1 - page->mediabox.y0;
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

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	NSString *docdir = [paths objectAtIndex: 0];
	NSError *error = nil;

	if (files) {
		[files release];
		files = nil;
	}

	files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath: docdir error: &error];
	if (error)
		files = paths;
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
	return [files count];
}

- (UITableViewCell*) tableView: (UITableView*)tableView cellForRowAtIndexPath: (NSIndexPath*)indexPath
{
	static NSString *cellid = @"MuCellIdent";
	UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier: cellid];
	if (!cell)
		cell = [[[UITableViewCell alloc] initWithStyle: UITableViewCellStyleDefault reuseIdentifier: cellid] autorelease];
	NSString *value = [files objectAtIndex: [indexPath row]];
	[[cell textLabel] setText: value];
	return cell;
}

- (void) tableView: (UITableView*)tableView didSelectRowAtIndexPath: (NSIndexPath*)indexPath
{
	NSString *filename = [files objectAtIndex: [indexPath row]];
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

- (UITableViewCell*) tableView: (UITableView*)tableView cellForRowAtIndexPath: (NSIndexPath*)indexPath
{
	static NSString *cellid = @"MuCellIdent";
	UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier: cellid];
	if (!cell)
		cell = [[[UITableViewCell alloc] initWithStyle: UITableViewCellStyleValue1 reuseIdentifier: cellid] autorelease];
	NSString *title = [titles objectAtIndex: [indexPath row]];
	NSString *page = [pages objectAtIndex: [indexPath row]];
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

	// make sure we're not doing any background processing
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

	pageviews = calloc(pdf_count_pages(xref), sizeof *pageviews);

	canvas = [[UIScrollView alloc] initWithFrame: CGRectMake(0,0,10,10)];
	[canvas setPagingEnabled: YES];
	[canvas setShowsHorizontalScrollIndicator: NO];
	[canvas setShowsVerticalScrollIndicator: NO];
	[canvas setDelegate: self];
	[self setView: canvas];

	[canvas addGestureRecognizer: [[UITapGestureRecognizer alloc] initWithTarget: self action: @selector(didSingleTap:)]];

	[self setTitle: nsfilename];

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

	return self;
}

- (void) dealloc
{
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
	[outline release];
	[canvas release];
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
				frame.origin.x = number * width;
				frame.origin.y = 0;
				frame.origin.x += (width - frame.size.width) / 2;
				frame.origin.y += (height - frame.size.height) / 2;
				[page setFrame: frame];
			} else {
				[page sizeToFit];
				[page setCenter: CGPointMake(number * width + width/2, height/2)];
			}
		} else {
			[page sizeToFit];
			[page setCenter: CGPointMake(number * width + width/2, height/2)];
		}
	}
}

- (void) viewWillAppear: (BOOL)animated
{
	CGSize size = [canvas frame].size;
	width = size.width;
	height = size.height;

	[canvas setContentInset: UIEdgeInsetsZero];
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];
}

- (void) scrollViewWillBeginDragging: (UIScrollView *)scrollView
{
	if (![[self navigationController] isNavigationBarHidden]) {
		[[self navigationController] setNavigationBarHidden: YES animated: YES];
		[canvas setContentInset: UIEdgeInsetsZero];
	}
}

- (void) scrollViewDidScroll: (UIScrollView*)scrollview
{
	if (width == 0)
		return; // not visible yet

	float x = [canvas contentOffset].x + width * 0.5f;
	int number = x / width;

#if 0
	for (int i = 0; i < pdf_count_pages(xref); i++)
		if (i != number)
			[self unloadPage: i];
	[self loadPage: number];
#else
	for (int i = 0; i < pdf_count_pages(xref); i++)
		if (i < number - 2 || i > number + 2)
			[self unloadPage: i];
	[self loadPage: number];
	[self loadPage: number + 1];
	[self loadPage: number - 1];
#endif

	current = number;
}

- (void) gotoPage: (int)number animated: (BOOL)animated
{
	if (number < 0)
		number = 0;
	if (number >= pdf_count_pages(xref))
		number = pdf_count_pages(xref) - 1;
	current = number;
	[canvas setContentOffset: CGPointMake(current * width, 0) animated: animated];
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

	// use max_width so we don't clamp the content offset too early during animation
	[canvas setContentInset: UIEdgeInsetsZero];
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * max_width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];
}

- (void) didRotateFromInterfaceOrientation: (UIInterfaceOrientation)o
{
	[canvas setContentInset: UIEdgeInsetsZero];
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];
}

- (void) didSingleTap: (UITapGestureRecognizer*)sender
{
	CGPoint p = [sender locationInView: canvas];
	CGPoint ofs = [canvas contentOffset];
	float x0 = width / 5;
	float x1 = width - x0;
	p.x -= ofs.x;
	p.y -= ofs.y;
	if (p.x < x0)
		[self gotoPage: current - 1 animated: YES];
	else if (p.x > x1)
		[self gotoPage: current + 1 animated: YES];
	else {
		UINavigationController *navigator = [self navigationController];
		if ([navigator isNavigationBarHidden])
			[navigator setNavigationBarHidden: NO animated: YES];
		else
			[navigator setNavigationBarHidden: YES animated: YES];
		[canvas setContentInset: UIEdgeInsetsZero];
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

	loadingImage = [[UIImage imageNamed: @"loading.png"] retain];

	library = [[MuLibraryController alloc] initWithStyle: UITableViewStylePlain];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];
	[[navigator navigationBar] setTranslucent: YES];
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
