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
#import "MuDialogCreator.h"

@interface MuPageViewNormal : UIScrollView <UIScrollViewDelegate,MuPageView>
{
	MuDocRef *docRef;
	fz_document *doc;
	fz_page *page;
	fz_display_list *page_list;
	fz_display_list *annot_list;
	int number;
	UIActivityIndicatorView *loadingView;
	fz_pixmap *image_pix;
	CGDataProviderRef imageData;
	UIImageView *imageView;
	fz_pixmap *tile_pix;
	CGDataProviderRef tileData;
	UIImageView *tileView;
	MuHitView *hitView;
	MuHitView *linkView;
	NSArray *widgetRects;
	CGSize pageSize;
	CGRect tileFrame;
	float tileScale;
	BOOL cancel;
	id<MuDialogCreator> dialogCreator;
}
- (id) initWithFrame: (CGRect)frame dialogCreator:(id<MuDialogCreator>)dia document: (MuDocRef *)aDoc page: (int)aNumber;
- (void) displayImage: (UIImage*)image;
- (void) resizeImage;
- (void) loadPage;
- (void) loadTile;
@end
