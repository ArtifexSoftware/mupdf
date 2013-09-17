#import <UIKit/UIKit.h>

int main(int argc, char *argv[])
{
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	int retVal;

	@try {
		retVal = UIApplicationMain(argc, argv, nil, @"MuAppDelegate");
	}
	@catch (NSException* exception) {
		NSLog(@"Uncaught exception %@", exception);
		NSLog(@"Stack trace: %@", [exception callStackSymbols]);
	}

	[pool release];
	return retVal;
}
