//
//  MuDocRef.m
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#include "common.h"
#import "MuDocRef.h"

@implementation MuDocRef

-(id) initWithFilename:(char *)aFilename;
{
	self = [super init];
	if (self)
	{
		dispatch_sync(queue, ^{});
		doc = fz_open_document(ctx, aFilename);
		if (!doc)
			self = nil;
	}
	return self;
}

-(void) dealloc
{
	__block fz_document *block_doc = doc;
	dispatch_async(queue, ^{
		fz_close_document(block_doc);
	});
	[super dealloc];
}

@end
