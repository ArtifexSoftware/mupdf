#import <UIKit/UIKit.h>
#import "MuAppDelegate.h"

int main(int argc, char *argv[])
{
	@autoreleasepool {
		@try {
			return UIApplicationMain(argc, argv, nil, NSStringFromClass([MuAppDelegate class]));
		}
		@catch (NSException* exception) {
			NSLog(@"Uncaught exception %@", exception);
			NSLog(@"Stack trace: %@", exception.callStackSymbols);
		}

		return 0;
	}
}
