//
//  MuAppDelegate.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

#import "MuLibraryController.h"

@interface MuAppDelegate : NSObject <UIApplicationDelegate, UINavigationControllerDelegate>
{
	UIWindow *window;
	UINavigationController *navigator;
	MuLibraryController *library;
}
@end
