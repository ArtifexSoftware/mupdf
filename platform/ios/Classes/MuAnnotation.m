#import "MuAnnotation.h"

@implementation MuAnnotation

@synthesize type, rect;

-(id) initFromAnnot:(fz_annot *)annot forDoc:(fz_document *)doc
{
	self = [super init];
	if (self)
	{
		fz_rect frect;
		type = pdf_annot_type((pdf_annot *)annot);
		fz_bound_annot(doc, annot, &frect);
		rect.origin.x = frect.x0;
		rect.origin.y = frect.y0;
		rect.size.width = frect.x1 - frect.x0;
		rect.size.height = frect.y1 - frect.y0;
	}
	return self;
}

+(MuAnnotation *) annotFromAnnot:(fz_annot *)annot forDoc:(fz_document *)doc
{
	return [[[MuAnnotation alloc] initFromAnnot:annot forDoc:doc] autorelease];
}
@end
