//
//  MuTapResult.m
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import "MuTapResult.h"

@implementation MuTapResult

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock {}

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

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock
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

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock
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

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock
{
	remoteLinkBlock(self);
}

@end