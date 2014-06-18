#import <UIKit/UIKit.h>

#import "MuLibraryController.h"

enum
{
	// use at most 128M for resource cache
	ResourceCacheMaxSize = 128<<20	// use at most 128M for resource cache
};

@interface MuAppDelegate : NSObject <UIApplicationDelegate, UINavigationControllerDelegate>
{
	UIWindow *window;
	UINavigationController *navigator;
	MuLibraryController *library;
}
@end
