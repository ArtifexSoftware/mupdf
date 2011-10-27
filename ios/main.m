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
	struct {
		NSMutableArray *titles;
		NSMutableArray *pages;
	} outline;
	UIScrollView *canvas;
	UIView **pageviews;
	UIView **loadviews;
	UIView *rotateview;
	char *cancel;
	int width; // current screen size
	int height;
	int current; // currently visible page
}
- (id) initWithFile: (NSString*)filename;
- (void) reconfigure;
- (void) layoutVisiblePages;
- (void) loadPage: (int)number;
- (void) unloadPage: (int)number;
- (void) gotoPage: (int)number animated: (BOOL)animated;
- (void) didSingleTap: (UITapGestureRecognizer*)sender;
- (void) toggleNavigationBar;
- (void) showOutline: (id)sender;
@end

@interface MuOutlineController : UITableViewController
{
	MuDocumentController *target;
	NSMutableArray *titles;
	NSMutableArray *pages;
}
- (id) initWithTarget: (MuDocumentController*)aTarget titles: (NSMutableArray*)aTitles pages: (NSMutableArray*)aPages;
@end

@interface MuAppDelegate : NSObject <UIApplicationDelegate, UINavigationControllerDelegate>
{
	UIWindow *window;
	UINavigationController *navigator;
	MuLibraryController *library;
}
@end

static dispatch_queue_t queue;
static fz_glyph_cache *glyphcache = NULL;
static MuAppDelegate *app = nil;

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
	if (error) {
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

@implementation MuOutlineController

- (id) initWithTarget: (MuDocumentController*)aTarget titles: (NSMutableArray*)aTitles pages: (NSMutableArray*)aPages
{
	self = [super initWithStyle: UITableViewStylePlain];
	if (self)
	{
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

	outline.titles = [[NSMutableArray alloc] init];
	outline.pages = [[NSMutableArray alloc] init];
	loadOutline(outline.titles, outline.pages, xref);

	pageviews = calloc(pdf_count_pages(xref), sizeof *pageviews);
	loadviews = calloc(pdf_count_pages(xref), sizeof *loadviews);
	cancel = malloc(pdf_count_pages(xref));

	canvas = [[UIScrollView alloc] initWithFrame: CGRectMake(0,0,10,10)];
	[canvas setPagingEnabled: YES];
	[canvas setBackgroundColor: [UIColor grayColor]];
	[canvas setShowsHorizontalScrollIndicator: NO];
	[canvas setShowsVerticalScrollIndicator: NO];
	[canvas setDelegate: self];
	[self setView: canvas];

	[canvas addGestureRecognizer: [[UITapGestureRecognizer alloc] initWithTarget: self action: @selector(didSingleTap:)]];

	[self setTitle: nsfilename];

	if ([outline.titles count])
	{
		[[self navigationItem] setRightBarButtonItem:
			[[UIBarButtonItem alloc]
				initWithBarButtonSystemItem: UIBarButtonSystemItemBookmarks
				target:self action:@selector(showOutline:)]];
	}

	[self setToolbarItems:
		[NSArray arrayWithObjects:
			[[UIBarButtonItem alloc]
				initWithBarButtonSystemItem: UIBarButtonSystemItemAction
				target:self action:@selector(toggleNavigationBar)],
			nil]];

	return self;
}

- (void) loadPage: (int)number
{
	UILabel *loading;

	if (number < 0 || number >= pdf_count_pages(xref))
		return;

	cancel[number] = NO;

	if (!loadviews[number] && !pageviews[number]) {
		loading = [[UILabel alloc] initWithFrame: CGRectMake(number * width + width/3, height/3, width/3, height/3)];
		[loading setText: [NSString stringWithFormat: @"Loading page %d of %d", number + 1, pdf_count_pages(xref)]];
		[loading setTextAlignment: UITextAlignmentCenter];
		[canvas addSubview: loading];
		loadviews[number] = loading;
printf("loadviews[current] added original %p\n", loadviews[number]);
		[loading release];
	}

	dispatch_async(queue, ^{
		if (cancel[number]) {
			dispatch_async(dispatch_get_main_queue(), ^{
				if (loadviews[number]) {
					printf("  load %d: canceled\n", number);
					[loadviews[number] removeFromSuperview];
					loadviews[number] = nil;
				}
			});
		} else if (!pageviews[number]) {
			printf("load %d: in worker thread\n", number);

			UIImageView *page = new_page_view(xref, number, width, height);

			CGRect frame = [page frame];
			frame.origin.x = number * width;
			frame.origin.x += (width - frame.size.width) / 2;
			frame.origin.y += (height - frame.size.height) / 2;
			[page setFrame: frame];

			pageviews[number] = page; // weak reference

			dispatch_async(dispatch_get_main_queue(), ^{
				printf("  load %d: adding view in main thread\n", number);
printf("loadviews[current] removed %p\n", loadviews[number]);
				[loadviews[number] removeFromSuperview];
				loadviews[number] = nil;
				[canvas addSubview: page];
				[page release];

				if (rotateview) {
					[rotateview removeFromSuperview];
					[rotateview release];
					rotateview = nil;
				}
			});
		}
	});
}

- (void) unloadPage: (int)number
{
	if (number < 0 || number >= pdf_count_pages(xref))
		return;

	cancel[number] = YES;

	dispatch_async(queue, ^{
		if (pageviews[number]) {
			printf("unload %d: in worker thread\n", number);
			UIView *page = pageviews[number];
			pageviews[number] = nil;
			dispatch_async(dispatch_get_main_queue(), ^{
				printf("  unload %d: removing view in main thread\n", number);
				[page removeFromSuperview];
			});
		}
	});
}

- (void) dealloc
{
	pdf_xref *self_xref = xref; // don't use self after dealloc has finished
	dispatch_async(queue, ^{
		printf("close xref\n");
		if (self_xref)
			pdf_free_xref(self_xref);
	});

	[outline.titles release];
	[outline.pages release];
	[canvas release];
	[super dealloc];
}

- (void) viewWillAppear: (BOOL)animated
{
	[super viewWillAppear: animated];
	[[self navigationController] setToolbarHidden: NO animated: NO];
	[self reconfigure];
}

- (void) viewDidDisappear: (BOOL)animated
{
	[super viewDidDisappear: animated];
	for (int i = 0; i < pdf_count_pages(xref); i++)
		[self unloadPage: i];
}

- (void) reconfigure
{
	CGSize size = [canvas frame].size;

	if (size.width == width && size.height == height)
		return;

	width = size.width;
	height = size.height;

	for (int i = 0; i < pdf_count_pages(xref); i++)
		[self unloadPage: i];

	[canvas setContentInset: UIEdgeInsetsZero];
	[canvas setContentSize: CGSizeMake(pdf_count_pages(xref) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0) animated: NO];

	if (rotateview) {
		CGRect frame = [rotateview frame];
		frame.origin.x = current * width;
		frame.origin.y = 0;
		frame.origin.x += (width - frame.size.width) / 2;
		frame.origin.y += (height - frame.size.height) / 2;
		[rotateview setFrame: frame];
	}

	[self layoutVisiblePages];
}

- (void) layoutVisiblePages
{
	int i;

	if (width == 0) return; // not visible yet

	float x = [canvas contentOffset].x + width * 0.5f;

	current = x / width;

#if 0
	for (i = 0; i < pdf_count_pages(xref); i++)
		if (i != current)
			[self unloadPage: i];
	[self loadPage: current];
#else
	for (i = 0; i < pdf_count_pages(xref); i++)
		if (i < current - 1 || i > current + 1)
			[self unloadPage: i];

	[self loadPage: current];
	[self loadPage: current + 1];
	[self loadPage: current - 1];
#endif
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

- (void) scrollViewDidScroll: (UIScrollView*)scrollview
{
	[self layoutVisiblePages];
}

- (BOOL) shouldAutorotateToInterfaceOrientation: (UIInterfaceOrientation)o
{
	return YES;
}

- (void) willRotateToInterfaceOrientation: (UIInterfaceOrientation)interfaceOrientation duration:(NSTimeInterval)duration
{
puts("willRotateToInterfaceOrientation");
	if (pageviews[current]) {
		rotateview = [[UIImageView alloc] initWithImage: [(UIImageView*)pageviews[current] image]];
		[rotateview setFrame: [pageviews[current] frame]];
		[canvas addSubview: rotateview];
	}

	for (int i = 0; i < pdf_count_pages(xref); i++)
		[self unloadPage: i];
	dispatch_sync(queue, ^{});
}

- (void) willAnimateRotationToInterfaceOrientation: (UIInterfaceOrientation)interfaceOrientation duration:(NSTimeInterval)duration
{
puts("willAnimateRotationToInterfaceOrientation");
	if (rotateview) {
		CGSize size = [canvas frame].size;
		CGRect frame = [rotateview frame];
		float scale = MIN(size.width / frame.size.width, size.height / frame.size.height);
		frame.size.width *= scale;
		frame.size.height *= scale;
		frame.origin.x = current * width;
		frame.origin.y = 0;
		frame.origin.x += (size.width - frame.size.width) / 2;
		frame.origin.y += (size.height - frame.size.height) / 2;
		[rotateview setFrame: frame];
	}
}

- (void) didRotateFromInterfaceOrientation: (UIInterfaceOrientation)o
{
puts("didRotateFromInterfaceOrientation");
	[self reconfigure];
}

- (void) didSingleTap: (UITapGestureRecognizer*)sender
{
	CGPoint p = [sender locationInView: canvas];
	CGPoint ofs = [canvas contentOffset];
	float x0 = width / 5;
	float x1 = width - x0;
	p.x -= ofs.x;
	p.y -= ofs.y;
	if (p.x < x0) [self gotoPage: current - 1 animated: YES];
	else if (p.x > x1) [self gotoPage: current + 1 animated: YES];
	else [self toggleNavigationBar];
}

- (void) toggleNavigationBar
{
	UINavigationController *navigator = [self navigationController];
	if ([navigator isNavigationBarHidden]) {
		[navigator setNavigationBarHidden: NO animated: NO];
		[navigator setToolbarHidden: NO animated: NO];
	} else {
		[navigator setNavigationBarHidden: YES animated: NO];
		[navigator setToolbarHidden: YES animated: NO];
	}
	[canvas setContentInset: UIEdgeInsetsZero];
}

- (void) showOutline: (id)sender
{
	MuOutlineController *ctl = [[MuOutlineController alloc] initWithTarget: self titles: outline.titles pages: outline.pages];
	[[self navigationController] pushViewController: ctl animated: YES];
	[ctl release];
}

@end

#pragma mark -

@implementation MuAppDelegate

- (BOOL) application: (UIApplication*)application didFinishLaunchingWithOptions: (NSDictionary*)launchOptions
{
	app = self;

	NSThread *foo = [[NSThread alloc] init];
	[foo start];
	[foo release];

	queue = dispatch_queue_create("com.artifex.mupdf.queue", NULL);

	glyphcache = fz_new_glyph_cache();

	library = [[MuLibraryController alloc] initWithStyle: UITableViewStylePlain];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];
	[[navigator navigationBar] setTranslucent: YES];
	[[navigator toolbar] setTranslucent: YES];
	[navigator setToolbarHidden: NO animated: NO];
	[navigator setDelegate: self];

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
printf("RUNNING OUT OF MEMORY SOON!!!111eleven\n");
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
