//
//  MuPageViewReflow.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "MuDocRef.h"
#import "MuPageView.h"

@interface MuPageViewReflow : UIWebView <UIWebViewDelegate,MuPageView>
{
	int number;
	float scale;
}

-(id) initWithFrame:(CGRect)frame document:(MuDocRef *)aDoc page:(int)aNumber;

@end
