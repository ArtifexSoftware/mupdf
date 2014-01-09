#include "common.h"

#import "MuAppDelegate.h"

@implementation MuAppDelegate

- (BOOL) application: (UIApplication*)application didFinishLaunchingWithOptions: (NSDictionary*)launchOptions
{
	NSString *filename;

	queue = dispatch_queue_create("com.artifex.mupdf.queue", NULL);

	// use at most 128M for resource cache
	ctx = fz_new_context(NULL, NULL, 128<<20);
	fz_register_document_handlers(ctx);

	screenScale = [[UIScreen mainScreen] scale];

	library = [[MuLibraryController alloc] initWithStyle: UITableViewStylePlain];

	navigator = [[UINavigationController alloc] initWithRootViewController: library];
	[[navigator navigationBar] setTranslucent: YES];
	[[navigator toolbar] setTranslucent: YES];
	[navigator setDelegate: self];

	window = [[UIWindow alloc] initWithFrame: [[UIScreen mainScreen] bounds]];
	[window setBackgroundColor: [UIColor grayColor]];
	[window setRootViewController: navigator];
	[window makeKeyAndVisible];

	filename = [[NSUserDefaults standardUserDefaults] objectForKey: @"OpenDocumentKey"];
	if (filename)
		[library openDocument: filename];

	filename = [launchOptions objectForKey: UIApplicationLaunchOptionsURLKey];
	NSLog(@"urlkey = %@\n", filename);

	return YES;
}

- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url sourceApplication:(NSString *)sourceApplication annotation:(id)annotation
{
	NSLog(@"openURL: %@\n", url);
	if ([url isFileURL]) {
		NSString *path = [url path];
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
