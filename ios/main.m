#import <UIKit/UIKit.h>

#undef ABS
#undef MIN
#undef MAX

#include "fitz/fitz.h"
#include "pdf/mupdf.h"
#include "xps/muxps.h"

@interface MuOutline : UITableViewController
{
}
@end

@interface MuDocument : UIViewController
{
}
@end

@interface MuLibrary : UITableViewController
{
	NSArray *files;
}
@end

@interface MuAppDelegate : NSObject <UIApplicationDelegate>
{
	UIWindow *window;
	UINavigationController *navigator;
	MuLibrary *library;
	MuDocument *document;
	MuOutline *outline;
}
- (void) doOpenDocument: (NSString*)filename;
- (void) doCloseDocument;
- (void) doShowOutline;
- (void) doHideOutline;
@end

static MuAppDelegate *app = nil;

#pragma mark -

@implementation MuOutline
@end

@implementation MuDocument
@end

#pragma mark -

@implementation MuLibrary

- (void) viewDidLoad
{
	[super viewDidLoad];

	[self setTitle: @"Library"];

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	NSString *docdir = [paths objectAtIndex: 0];
	NSError *error = nil;
	files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath: docdir error: &error];
	if (error)
		files = paths;
	[files retain];
}

- (void) dealloc
{
	[files release];
	[super dealloc];
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
	[app doOpenDocument: filename];
}

@end

#pragma mark -

@implementation MuAppDelegate

- (BOOL) application: (UIApplication*)application didFinishLaunchingWithOptions: (NSDictionary*)launchOptions
{
	app = self;

	library = [[MuLibrary alloc] initWithStyle: UITableViewStylePlain];

	document = [[MuDocument alloc] init];
	[[document view] setBackgroundColor: [UIColor yellowColor]];

	outline = [[MuOutline alloc] initWithStyle: UITableViewStylePlain];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];

	window = [[UIWindow alloc] initWithFrame: [[UIScreen mainScreen] bounds]];
	[window addSubview: [navigator view]];
	[window makeKeyAndVisible];

	return YES;
}

//	[library presentModalViewController: document animated: NO];
//	[library dismissModalViewControllerAnimated: NO];

- (void) doShowOutline
{
	[outline setTitle: @"Table of Contents"];
	[navigator pushViewController: document animated: YES];
}

- (void) doHideOutline
{
	[navigator popViewControllerAnimated: YES];
}

- (void) doOpenDocument: (NSString*)filename
{
	[document setTitle: filename];
	[navigator pushViewController: document animated: YES];
}

- (void) doCloseDocument
{
	[navigator popViewControllerAnimated: YES];
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
	/*
	 Use this method to release shared resources, save user data, invalidate timers,
	 and store enough application state information to restore your application to
	 its current state in case it is terminated later. 
	 If your application supports background execution,
	 called instead of applicationWillTerminate: when the user quits.
	 */
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
	/*
	 Called as part of	transition from the background to the
	 inactive state: here you can undo many of the changes made 
	 on entering the background.
	 */
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
	/*
	 Restart any tasks that were paused (or not yet started) while
	 the application was inactive. If the application was previously
	 in the background, optionally refresh the user interface.
	 */
}

- (void)applicationWillTerminate:(UIApplication *)application {
	/*
	 Called when the application is about to terminate.
	 See also applicationDidEnterBackground:.
	 */
}

- (void)applicationDidReceiveMemoryWarning:(UIApplication *)application {
	/*
	 Free up as much memory as possible by purging cached data objects that can
	 be recreated (or reloaded from disk) later.
	 */
}

- (void) dealloc
{
	[document release];
	[library release];
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
