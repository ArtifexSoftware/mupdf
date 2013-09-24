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

#import "MuDocRef.h"
#include "MuHitView.h"

@interface MuPageView : UIScrollView <UIScrollViewDelegate>
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
- (id) initWithFrame: (CGRect)frame document: (MuDocRef*)aDoc page: (int)aNumber;
- (void) displayImage: (UIImage*)image;
- (void) resizeImage;
- (void) loadPage;
- (void) loadTile;
- (void) willRotate;
- (void) resetZoomAnimated: (BOOL)animated;
- (void) showSearchResults: (int)count;
- (void) clearSearchResults;
- (void) showLinks;
- (void) hideLinks;
- (int) number;
@end
