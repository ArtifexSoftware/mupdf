//
//  MuTapResult.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@class MuTapResultInternalLink;
@class MuTapResultExternalLink;
@class MuTapResultRemoteLink;
@class MuTapResultWidget;

@interface MuTapResult : NSObject
-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock
		caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock
		caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock
		caseWidget:(void (^)(MuTapResultWidget *))widgetBlock;
@end

@interface MuTapResultInternalLink : MuTapResult
{
	int pageNumber;
}
@property(readonly) int pageNumber;
-(id)initWithPageNumber:(int)aNumber;
@end

@interface MuTapResultExternalLink : MuTapResult
{
	NSString *url;
}
@property(readonly) NSString *url;
-(id)initWithUrl:(NSString *)aString;
@end

@interface MuTapResultRemoteLink : MuTapResult
{
	NSString *fileSpec;
	int pageNumber;
	BOOL newWindow;
}
@property(readonly) NSString *fileSpec;
@property(readonly) int pageNumber;
@property(readonly) BOOL newWindow;
-(id)initWithFileSpec:(NSString *)aString pageNumber:(int)aNumber newWindow:(BOOL)aBool;
@end

@interface MuTapResultWidget : MuTapResult
@end
