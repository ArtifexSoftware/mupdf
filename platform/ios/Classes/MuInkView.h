//
//  MuInkView.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface MuInkView : UIView
{
	CGSize pageSize;
	NSMutableArray *curves;
	UIColor *color;
}

@property(readonly) NSArray *curves;

- (id) initWithPageSize:(CGSize)pageSize;

@end
