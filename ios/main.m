#import <UIKit/UIKit.h>

#undef ABS
#undef MIN
#undef MAX

#include "fitz/fitz.h"
#include "pdf/mupdf.h"
#include "xps/muxps.h"

@interface MuLibraryController : UITableViewController
{
	NSArray *files;
}
- (void) reload;
- (void) openDocument: (NSString*)filename;
@end

@interface MuDocumentController : UIViewController <UIScrollViewDelegate>
{
	pdf_xref *xref;
	UIScrollView *canvas;
	UIView **pageviews;
	int width; // current screen size
	int height;
	int current; // currently visible page
}
- (id) initWithFile: (NSString*)filename;
- (void) reconfigure;
- (void) loadPage: (int)number;
- (void) unloadPage: (int)number;
- (void) gotoPage: (int)number;
- (void) didSingleTap: (UITapGestureRecognizer*)sender;
- (void) toggleNavigationBar;
@end

@interface MuAppDelegate : NSObject <UIApplicationDelegate, UINavigationControllerDelegate>
{
	UIWindow *window;
	UINavigationController *navigator;
	MuLibraryController *library;
}
@end

static fz_glyph_cache *glyphcache = NULL;

static MuAppDelegate *app = nil;

#pragma mark -

static int get_page_number(pdf_xref *xref, pdf_link *link)
{
	if (link->kind == PDF_LINK_GOTO)
		return pdf_find_page_number(xref, fz_array_get(link->dest, 0));
	return 0;
}

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

static void releasePixmap(void *info, const void *data, size_t size)
{
	fz_drop_pixmap(info);
}

static UIImage *imageWithPixmap(fz_pixmap *pix)
{
	CGDataProviderRef cgdata = CGDataProviderCreateWithData(pix, pix->samples, pix->w * 4 * pix->h, releasePixmap);
	CGImageRef cgimage = CGImageCreate(pix->w, pix->h, 8, 32, 4 * pix->w,
			CGColorSpaceCreateDeviceRGB(),
			kCGBitmapByteOrderDefault,
			cgdata, NULL, NO, kCGRenderingIntentDefault);
	UIImage *image = [UIImage imageWithCGImage: cgimage];
	CGDataProviderRelease(cgdata);
	CGImageRelease(cgimage);
	return image;
}

static UIImageView *new_page_view(pdf_xref *xref, int number, float width, float height)
{
	fz_bbox bbox;
	fz_matrix ctm;
	fz_device *dev;
	fz_pixmap *pix;
	pdf_page *page;
	fz_error error;
	float scale, hscale, vscale;

	error = pdf_load_page(&page, xref, number);
	if (error)
	{
		showAlert(@"Cannot load page");
		return [[UIImageView alloc] initWithImage: [UIImage imageNamed: @"mupdf_icon.png"]];
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

	return [[UIImageView alloc] initWithImage: imageWithPixmap(pix)];
}

#pragma mark -

@implementation MuLibraryController

- (void) reload
{
	[self setTitle: @"Library"];

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
	[self openDocument: filename];
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

@implementation MuDocumentController

- (id) initWithFile: (NSString*)nsfilename
{
	fz_error error;
	char filename[PATH_MAX];
	char *password = "";

	self = [super init];
	if (!self)
		return nil;

	strcpy(filename, [NSHomeDirectory() UTF8String]);
	strcat(filename, "/Documents/");
	strcat(filename, [nsfilename UTF8String]);

	NSLog(@"filename = '%s'\n", filename);

	error = pdf_open_xref(&xref, filename, password);
	if (error)
	{
		showAlert(@"Cannot open PDF file");
		[self release];
		return nil;
	}

	error = pdf_load_page_tree(xref);
	if (error)
	{
		showAlert(@"Cannot open document");
		[self release];
		return nil;
	}

	[self setTitle: nsfilename];

	canvas = [[UIScrollView alloc] initWithFrame: CGRectMake(0,0,10,10)];
	[canvas setPagingEnabled: YES];
	[canvas setBackgroundColor: [UIColor grayColor]];
	[canvas setShowsHorizontalScrollIndicator: NO];
	[canvas setShowsVerticalScrollIndicator: NO];
	[canvas setDelegate: self];
	[self setView: canvas];

	[canvas addGestureRecognizer: [[UITapGestureRecognizer alloc] initWithTarget: self action: @selector(didSingleTap:)]];

	current = 0;
	pageviews = calloc(pdf_count_pages(xref), sizeof *pageviews);

	return self;
}

- (void) dealloc
{
puts("document controller closed");
	if (xref)
	{
		for (int i = 0; i < pdf_count_pages(xref); i++)
			[self unloadPage: i];
		pdf_free_xref(xref);
		xref = NULL;
	}
	[canvas release];
	[super dealloc];
}

- (BOOL) shouldAutorotateToInterfaceOrientation: (UIInterfaceOrientation)o
{
	return YES;
}

- (void) didRotateFromInterfaceOrientation: (UIInterfaceOrientation)o
{
	[self reconfigure];
}

- (void) viewWillAppear: (BOOL)animated
{
	[self reconfigure];
}

- (void) reconfigure
{
	CGSize size = [canvas frame].size;

	if (size.width == width && size.height == height)
		return;

	width = size.width;
	height = size.height;

printf("reconfig w=%g h=%g\n", size.width, size.height);

	// facing pages mode in landscape
	// if (size.width > size.height) size.width *= 0.5;

	for (int i = 0; i < pdf_count_pages(xref); i++)
		[self unloadPage: i];

	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, 10)];
	[canvas setContentOffset: CGPointMake(current * width, 0) animated: NO];
	[canvas setContentInset: UIEdgeInsetsZero];

	[self scrollViewDidScroll: canvas];
}

- (void) loadPage: (int)number
{
	if (number < 0 || number >= pdf_count_pages(xref))
		return;
	if (!pageviews[number])
	{
printf("load page %d\n", number);
		UIImageView *page = new_page_view(xref, number, width, height);

		CGRect frame = [page frame];
		frame.origin.x = number * width;
		frame.origin.x += (width - frame.size.width) / 2;
		frame.origin.y += (height - frame.size.height) / 2;
		[page setFrame: frame];

		[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, height)];
		[canvas addSubview: page];

		pageviews[number] = page;
	}
}

- (void) unloadPage: (int)number
{
	if (number < 0 || number >= pdf_count_pages(xref))
		return;
	if (pageviews[number])
	{
printf("unload %d\n", number);
		[pageviews[number] removeFromSuperview];
		[pageviews[number] release];
		pageviews[number] = nil;
	}
}

- (void) gotoPage: (int)number
{
	if (number < 0)
		number = 0;
	if (number >= pdf_count_pages(xref))
		number = pdf_count_pages(xref) - 1;
	current = number;
	[canvas setContentOffset: CGPointMake(current * width, 0) animated: YES];
}

- (void) scrollViewDidScroll: (UIScrollView*)scrollview
{
	float x = [canvas contentOffset].x + width * 0.5f;
	int i;

	current = x / width;

	for (i = 0; i < current - 3; i++)
		[self unloadPage: i];
	for (i = current + 3; i < pdf_count_pages(xref); i++)
		[self unloadPage: i];

	[self loadPage: current];
	[self loadPage: current - 1];
	[self loadPage: current + 1];
}

- (void) didSingleTap: (UITapGestureRecognizer*)sender
{
	CGPoint p = [sender locationInView: canvas];
	CGPoint ofs = [canvas contentOffset];
	float x0 = width / 5;
	float x1 = width - x0;
	p.x -= ofs.x;
	p.y -= ofs.y;
	if (p.x < x0) [self gotoPage: current - 1];
	else if (p.x > x1) [self gotoPage: current + 1];
	else [self toggleNavigationBar];
}

- (void) toggleNavigationBar
{
	UINavigationController *navigator = [self navigationController];
	if ([navigator isNavigationBarHidden]) {
		[navigator setNavigationBarHidden: NO];
	} else {
		[navigator setNavigationBarHidden: YES];
	}
	[canvas setContentInset: UIEdgeInsetsZero];
}

@end

#pragma mark -

@implementation MuAppDelegate

- (BOOL) application: (UIApplication*)application didFinishLaunchingWithOptions: (NSDictionary*)launchOptions
{
	app = self;

	glyphcache = fz_new_glyph_cache();

	library = [[MuLibraryController alloc] initWithStyle: UITableViewStylePlain];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];
	[[navigator navigationBar] setTranslucent: YES];
	[navigator setDelegate: app];

	window = [[UIWindow alloc] initWithFrame: [[UIScreen mainScreen] bounds]];
	[window addSubview: [navigator view]];
	[window makeKeyAndVisible];

	return YES;
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
	/*
	 Use this method to release shared resources, save user data, invalidate timers,
	 and store enough application state information to restore your application to
	 its current state in case it is terminated later.
	 If your application supports background execution,
	 called instead of applicationWillTerminate: when the user quits.
	 */
printf("applicationDidEnterBackground!\n");
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
	/*
	 Called as part of	transition from the background to the
	 inactive state: here you can undo many of the changes made
	 on entering the background.
	 */
printf("applicationWillEnterForeground!\n");
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
	/*
	 Restart any tasks that were paused (or not yet started) while
	 the application was inactive. If the application was previously
	 in the background, optionally refresh the user interface.
	 */
printf("applicationDidBecomeActive!\n");
	[library reload];
}

- (void)applicationWillTerminate:(UIApplication *)application
{
	/*
	 Called when the application is about to terminate.
	 See also applicationDidEnterBackground:.
	 */
}

- (void)applicationDidReceiveMemoryWarning:(UIApplication *)application
{
	/*
	 Free up as much memory as possible by purging cached data objects that can
	 be recreated (or reloaded from disk) later.
	 */
}

- (void) dealloc
{
	[library release];
	[navigator release];
	[window release];
	[super dealloc];
}

@end

#pragma mark -

int main(int argc, char *argv[])
{
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	int retVal = UIApplicationMain(argc, argv, nil, @"MuAppDelegate");
	[pool release];
	return retVal;
}
