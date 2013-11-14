//
//  MuTextSelectView.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#include "common.h"

@interface MuTextSelectView : UIView
{
	NSArray *words;
	CGSize pageSize;
	UIColor *color;
	CGPoint start;
	CGPoint end;
}
- (id) initWithWords:(NSArray *)_words pageSize:(CGSize)_pageSize;
- (NSArray *) selectionRects;
- (NSString *) selectedText;
@end
