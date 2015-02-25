#import <UIKit/UIKit.h>

#import "MuLibraryController.h"

enum
{
	ResourceCacheMaxSize = 128<<20	/**< use at most 128M for resource cache */
};

@interface MuAppDelegate : NSObject <UIApplicationDelegate>
@end
