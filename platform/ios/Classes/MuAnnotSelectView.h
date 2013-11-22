//
//  MuAnnotSelectView.h
//  MuPDF
//
//  Created by Paul Gardiner on 21/11/2013.
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "MuAnnotation.h"

@interface MuAnnotSelectView : UIView
{
	MuAnnotation *annot;
	CGSize pageSize;
	UIColor *color;
}
- (id) initWithAnnot:(MuAnnotation *)_annot pageSize:(CGSize)_pageSize;
@end
