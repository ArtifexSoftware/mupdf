#import "MuAnnotation.h"

@implementation MuAnnotation
{
	int type;
	CGRect rect;
}

@synthesize type, rect;

-(id) initFromAnnot:(fz_annot *)annot forPage:(fz_page *)page;
{
	self = [super init];
	if (self)
	{
		fz_rect frect;
		type = pdf_annot_type(ctx, (pdf_annot *)annot);
		fz_bound_annot(ctx, page, annot, &frect);
		rect.origin.x = frect.x0;
		rect.origin.y = frect.y0;
		rect.size.width = frect.x1 - frect.x0;
		rect.size.height = frect.y1 - frect.y0;
	}
	return self;
}

+(MuAnnotation *) annotFromAnnot:(fz_annot *)annot forPage:(fz_page *)page;
{
	return [[[MuAnnotation alloc] initFromAnnot:annot forPage:page] autorelease];
}
@end
