//
//  MuTapResult.m
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import "MuTapResult.h"

@implementation MuTapResult

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock {}
@end


@implementation MuTapResultInternalLink

@synthesize pageNumber;

-(id) initWithPageNumber:(int)aNumber
{
	self = [super init];
	if (self)
	{
		pageNumber = aNumber;
	}
	return self;
}

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock
{
	internalLinkBlock(self);
}

@end


@implementation MuTapResultExternalLink

@synthesize url;

-(id) initWithUrl:(NSString *)aString
{
	self = [super init];
	if (self)
	{
		url = [aString retain];
	}
	return self;
}

-(void) dealloc
{
	[url release];
	[super dealloc];
}

-(void)	switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock
{
	externalLinkBlock(self);
}

@end


@implementation MuTapResultRemoteLink

@synthesize fileSpec, pageNumber, newWindow;

-(id) initWithFileSpec:(NSString *)aString pageNumber:(int)aNumber newWindow:(BOOL)aBool
{
	self = [super init];
	if (self)
	{
		fileSpec = [aString retain];
		pageNumber = aNumber;
		newWindow = aBool;
	}
	return  self;
}

-(void) dealloc
{
	[fileSpec release];
	[super dealloc];
}

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock
{
	remoteLinkBlock(self);
}

@end


@implementation MuTapResultWidget

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock
{
	widgetBlock(self);
}

@end