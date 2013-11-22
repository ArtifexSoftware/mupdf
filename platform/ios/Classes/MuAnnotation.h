//
//  MuAnnotation.h
//  MuPDF
//
//  Created by Paul Gardiner on 20/11/2013.
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#include "common.h"
#include "mupdf/pdf.h"
#import <Foundation/Foundation.h>

@interface MuAnnotation : NSObject
{
	int type;
	CGRect rect;
}
-(id) initFromAnnot:(fz_annot *)annot forDoc:(fz_document *)doc;
@property(readonly) int type;
@property(readonly) CGRect rect;
+(MuAnnotation *) annotFromAnnot:(fz_annot *)annot forDoc:(fz_document *)doc;
@end
