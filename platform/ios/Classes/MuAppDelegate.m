#include "common.h"
#include "mupdf/fitz.h"

#import "MuAppDelegate.h"

#ifdef CRASHLYTICS_ENABLE
#import <Fabric/Fabric.h>
#import <Crashlytics/Crashlytics.h>
#endif

@interface MuAppDelegate () <UINavigationControllerDelegate>
@end

@implementation MuAppDelegate
{
	UIWindow *window;
	UINavigationController *navigator;
	MuLibraryController *library;
	BOOL _isInBackground;
}

- (BOOL) application: (UIApplication*)application didFinishLaunchingWithOptions: (NSDictionary*)launchOptions
{
	NSString *filename;

	queue = dispatch_queue_create("com.artifex.mupdf.queue", NULL);

	ctx = fz_new_context(NULL, NULL, ResourceCacheMaxSize);
	fz_register_document_handlers(ctx);

#ifdef CRASHLYTICS_ENABLE
	NSLog(@"Starting Crashlytics");
	[Fabric with:@[[Crashlytics class]]];
#endif

	screenScale = [UIScreen mainScreen].scale;

	library = [[MuLibraryController alloc] initWithStyle: UITableViewStylePlain];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];
	[navigator.navigationBar setTranslucent: YES];
	[navigator.toolbar setTranslucent: YES];
	navigator.delegate = self;

	window = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
	window.backgroundColor = [UIColor grayColor];
	window.rootViewController = navigator;
	[window makeKeyAndVisible];

	filename = [[NSUserDefaults standardUserDefaults] objectForKey: @"OpenDocumentKey"];
	if (filename)
		[library openDocument: filename];

	filename = launchOptions[UIApplicationLaunchOptionsURLKey];
	NSLog(@"urlkey = %@\n", filename);

	return YES;
}

- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url sourceApplication:(NSString *)sourceApplication annotation:(id)annotation
{
	NSLog(@"openURL: %@\n", url);
	if (url.fileURL) {
		NSString *path = url.path;
		NSString *dir = [NSString stringWithFormat: @"%@/Documents/", NSHomeDirectory()];
		path = [path stringByReplacingOccurrencesOfString:@"/private" withString:@""];
		path = [path stringByReplacingOccurrencesOfString:dir withString:@""];
		NSLog(@"file relative path: %@\n", path);
		[library openDocument:path];
		return YES;
	}
	return NO;
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
	printf("applicationDidEnterBackground!\n");
	[[NSUserDefaults standardUserDefaults] synchronize];
	_isInBackground = YES;
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
	printf("applicationWillEnterForeground!\n");
	_isInBackground = NO;
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
	NSLog(@"applicationDidReceiveMemoryWarning");
	int success = fz_shrink_store(ctx, _isInBackground ? 0 : 50);
	NSLog(@"fz_shrink_store: success = %d", success);
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
