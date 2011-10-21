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
@end

@interface MuOutlineController : UITableViewController { NSArray *pages; } @end
@interface MuDocumentController : UIViewController { } @end

@interface MuAppDelegate : NSObject <UIApplicationDelegate, UIScrollViewDelegate, UINavigationControllerDelegate>
{
	UIWindow *window;
	UINavigationController *navigator;
	UIScrollView *canvas;
	MuLibraryController *library;
	MuDocumentController *document;
	MuOutlineController *outline;
	UIView **pageviews;
	int width; // current screen size
	int height;
	int current; // currently visible page
}
- (void) onOpenDocument: (NSString*)filename;
- (void) closeDocument;
- (void) onShowOutline;
- (void) onHideOutline;
- (void) onReconfigure;
- (void) loadPage: (int)number;
- (void) unloadPage: (int)number;
- (void) onGotoPage: (int)number;
- (void) toggleNavigationBar;
- (void) onSingleTap: (UITapGestureRecognizer*)sender;
@end

static fz_glyph_cache *glyphcache = NULL;
static pdf_xref *xref = NULL;
static MuAppDelegate *app = nil;

#pragma mark -

static void show_alert(NSString *msg)
{
	UIAlertView *alert = [[UIAlertView alloc]
		initWithTitle: @"Error"
		message: msg
		delegate: nil
		cancelButtonTitle: @"Okay"
		otherButtonTitles: nil];
	[alert show];
	[alert release];
}

static int get_page_number(pdf_xref *xref, pdf_link *link)
{
	if (link->kind == PDF_LINK_GOTO)
		return pdf_find_page_number(xref, fz_array_get(link->dest, 0));
	return 0;
}

static void release_pixmap(void *info, const void *data, size_t size)
{
	fz_drop_pixmap(info);
}

static UIImage *convert_pixmap(fz_pixmap *pix)
{
	CGDataProviderRef cgdata = CGDataProviderCreateWithData(pix, pix->samples, pix->w * 4 * pix->h, release_pixmap);
	CGImageRef cgimage = CGImageCreate(pix->w, pix->h, 8, 32, 4 * pix->w,
			CGColorSpaceCreateDeviceRGB(),
			kCGBitmapByteOrderDefault,
			cgdata, NULL, NO, kCGRenderingIntentDefault);
	UIImage *image = [UIImage imageWithCGImage: cgimage];
	CGDataProviderRelease(cgdata);
	CGImageRelease(cgimage);
	return image;
}

// TODO: custom view with hyperlinks
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
		show_alert(@"Cannot load page");
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

	return [[UIImageView alloc] initWithImage: convert_pixmap(pix)];
}

#pragma mark -

@implementation MuDocumentController

- (BOOL) shouldAutorotateToInterfaceOrientation: (UIInterfaceOrientation)o
{
	return YES;
}

- (void) didRotateFromInterfaceOrientation: (UIInterfaceOrientation)o
{
	[app onReconfigure];
}

@end

@implementation MuOutlineController
@end

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

- (NSInteger) tableView: (UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
	return [files count];
}

- (UITableViewCell*) tableView: (UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
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
	[app onOpenDocument: filename];
}

@end

#pragma mark -

@implementation MuAppDelegate

- (BOOL) application: (UIApplication*)application didFinishLaunchingWithOptions: (NSDictionary*)launchOptions
{
	CGRect viewframe;
	app = self;

	glyphcache = fz_new_glyph_cache();

	library = [[MuLibraryController alloc] initWithStyle: UITableViewStylePlain];
	// outline = [[MuOutlineController alloc] initWithStyle: UITableViewStylePlain];

	document = [[MuDocumentController alloc] init];
	// [document setWantsFullScreenLayout: YES];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];
	[[navigator navigationBar] setTranslucent: YES];
	[navigator setDelegate: app];

	viewframe = [[[navigator topViewController] view] frame];

	canvas = [[UIScrollView alloc] initWithFrame: viewframe];
	[canvas setPagingEnabled: YES];
	[canvas setBackgroundColor: [UIColor grayColor]];
	[canvas setShowsHorizontalScrollIndicator: NO];
	[canvas setShowsVerticalScrollIndicator: NO];
	// [canvas setDirectionalLockEnabled: YES];
	[canvas setDelegate: app];
	[document setView: canvas];

	[canvas addGestureRecognizer: [[UITapGestureRecognizer alloc] initWithTarget: self action: @selector(onSingleTap:)]];

	window = [[UIWindow alloc] initWithFrame: [[UIScreen mainScreen] bounds]];
	[window addSubview: [navigator view]];
	[window makeKeyAndVisible];

	return YES;
}

- (void) onShowOutline
{
	[outline setTitle: @"Table of Contents"];
	[navigator pushViewController: outline animated: YES];
}

- (void) onHideOutline
{
	[navigator popViewControllerAnimated: YES];
}

- (void) onOpenDocument: (NSString*)nsfilename
{
	fz_error error;
	char filename[PATH_MAX];
	char *password = "";

	strcpy(filename, [NSHomeDirectory() UTF8String]);
	strcat(filename, "/Documents/");
	strcat(filename, [nsfilename UTF8String]);

	NSLog(@"filename = '%s'\n", filename);

	error = pdf_open_xref(&xref, filename, password);
	if (error)
	{
		show_alert(@"Cannot open document");
		return;
	}

	error = pdf_load_page_tree(xref);
	if (error)
	{
		show_alert(@"Cannot load page list");
		return;
	}

	[document setTitle: nsfilename];

	current = 0;
	pageviews = calloc(pdf_count_pages(xref), sizeof *pageviews);

	[navigator pushViewController: document animated: YES];

	[self onReconfigure];
}

- (void) closeDocument
{
	if (xref)
	{
		for (int i = 0; i < pdf_count_pages(xref); i++)
			[self unloadPage: i];
		pdf_free_xref(xref);
		xref = NULL;
	}
}

- (void) onReconfigure
{
	CGSize size = [canvas frame].size;
	int i;

	if (size.width == width && size.height != height)
		return;

	width = [canvas frame].size.width;
	height = [canvas frame].size.height;
printf("reconfig w=%d h=%d\n", width, height);

	// facing pages mode in landscape
	// if (width > height) width *= 0.5;

	for (i = 0; i < pdf_count_pages(xref); i++)
		[self unloadPage: i];

	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, 10)];
	[canvas setContentOffset: CGPointMake(current * width, 0) animated: NO];

	[app scrollViewDidScroll: canvas];
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

- (void) onGotoPage: (int)number
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
	float x = [canvas contentOffset].x;
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

- (void) onSingleTap: (UITapGestureRecognizer*)sender
{
	CGPoint p = [sender locationInView: canvas];
	CGPoint ofs = [canvas contentOffset];
	float x0 = width / 5;
	float x1 = width - x0;
	p.x -= ofs.x;
	p.y -= ofs.y;
	if (p.x < x0) [self onGotoPage: current - 1];
	else if (p.x > x1) [self onGotoPage: current + 1];
	else [self toggleNavigationBar];
}

- (void) toggleNavigationBar
{
	if ([navigator isNavigationBarHidden])
		[navigator setNavigationBarHidden: NO];
	else
		[navigator setNavigationBarHidden: YES];
	[canvas setContentInset: UIEdgeInsetsZero];
}

- (void) navigationController:(UINavigationController *)navigationController didShowViewController:(UIViewController *)viewController animated:(BOOL)animated
{
	// popped back to document picker
	if (viewController == library)
		[self closeDocument];
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
	[canvas release];
	[document release];
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
