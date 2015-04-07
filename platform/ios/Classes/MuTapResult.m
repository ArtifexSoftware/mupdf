#import "MuTapResult.h"

@implementation MuTapResult
-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock caseAnnotation:(void (^)(MuTapResultAnnotation *))annotationBlock {}
@end

@implementation MuTapResultInternalLink
{
	int pageNumber;
}

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

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock caseAnnotation:(void (^)(MuTapResultAnnotation *))annotationBlock
{
	internalLinkBlock(self);
}

@end

@implementation MuTapResultExternalLink
{
	NSString *url;
}

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

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock caseAnnotation:(void (^)(MuTapResultAnnotation *))annotationBlock
{
	externalLinkBlock(self);
}

@end

@implementation MuTapResultRemoteLink
{
	NSString *fileSpec;
	int pageNumber;
	BOOL newWindow;
}

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
	return self;
}

-(void) dealloc
{
	[fileSpec release];
	[super dealloc];
}

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock caseAnnotation:(void (^)(MuTapResultAnnotation *))annotationBlock
{
	remoteLinkBlock(self);
}

@end

@implementation MuTapResultWidget

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock caseAnnotation:(void (^)(MuTapResultAnnotation *))annotationBlock
{
	widgetBlock(self);
}

@end

@implementation MuTapResultAnnotation
{
	MuAnnotation *annot;
}

@synthesize annot;

-(id) initWithAnnotation:(MuAnnotation *)aAnnot
{
	self = [super init];
	if (self)
	{
		annot = [aAnnot retain];
	}
	return self;
}

-(void) dealloc
{
	[annot release];
	[super dealloc];
}

-(void) switchCaseInternal:(void (^)(MuTapResultInternalLink *))internalLinkBlock caseExternal:(void (^)(MuTapResultExternalLink *))externalLinkBlock caseRemote:(void (^)(MuTapResultRemoteLink *))remoteLinkBlock caseWidget:(void (^)(MuTapResultWidget *))widgetBlock caseAnnotation:(void (^)(MuTapResultAnnotation *))annotationBlock
{
	annotationBlock(self);
}

@end
