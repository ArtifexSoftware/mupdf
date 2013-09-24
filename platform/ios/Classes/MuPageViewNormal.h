//
//  MuPageView.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

#undef ABS
#undef MIN
#undef MAX

#include "mupdf/fitz.h"

#import "MuHitView.h"
#import "MuPageView.h"
#import "MuDocRef.h"

@interface MuPageViewNormal : UIScrollView <UIScrollViewDelegate,MuPageView>
{
	MuDocRef *docRef;
	fz_document *doc;
	fz_page *page;
	int number;
	UIActivityIndicatorView *loadingView;
	UIImageView *imageView;
	UIImageView *tileView;
	MuHitView *hitView;
	MuHitView *linkView;
	CGSize pageSize;
	CGRect tileFrame;
	float tileScale;
	BOOL cancel;
}
- (id) initWithFrame: (CGRect)frame document: (MuDocRef *)aDoc page: (int)aNumber;
- (void) displayImage: (UIImage*)image;
- (void) resizeImage;
- (void) loadPage;
- (void) loadTile;
@end
