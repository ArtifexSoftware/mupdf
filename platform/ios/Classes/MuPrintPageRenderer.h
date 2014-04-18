//
//  MuPrintPageRenderer.h
//  MuPDF
//
//  Copyright (c) 2014 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <MuDocRef.h>

@interface MuPrintPageRenderer : UIPrintPageRenderer
{
	MuDocRef *docRef;
}

-(id) initWithDocRef:(MuDocRef *) docRef;

@end
