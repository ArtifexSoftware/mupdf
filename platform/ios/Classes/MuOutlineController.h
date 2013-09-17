//
//  MuOutlineController.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface MuOutlineController : UITableViewController
{
	id target;
	NSMutableArray *titles;
	NSMutableArray *pages;
}
- (id) initWithTarget: (id)aTarget titles: (NSMutableArray*)aTitles pages: (NSMutableArray*)aPages;
@end
