#import "MuAnnotation.h"

@implementation MuAnnotation
{
	int type;
	CGRect rect;
}

@synthesize type, rect;

-(instancetype) initFromAnnot:(fz_annot *)annot;
{
	self = [super init];
	if (self)
	{
		fz_rect frect;
		type = pdf_annot_type(ctx, (pdf_annot *)annot);
		fz_bound_annot(ctx, annot, &frect);
		rect.origin.x = frect.x0;
		rect.origin.y = frect.y0;
		rect.size.width = frect.x1 - frect.x0;
		rect.size.height = frect.y1 - frect.y0;
	}
	return self;
}

+(MuAnnotation *) annotFromAnnot:(fz_annot *)annot;
{
	return [[[MuAnnotation alloc] initFromAnnot:annot] autorelease];
}
@end
