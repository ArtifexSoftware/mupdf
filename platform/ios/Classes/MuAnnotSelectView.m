#import "MuAnnotSelectView.h"

@implementation MuAnnotSelectView
{
	MuAnnotation *annot;
	CGSize pageSize;
	UIColor *color;
}

- (id)initWithAnnot:(MuAnnotation *)_annot pageSize:(CGSize)_pageSize
{
	self = [super initWithFrame:CGRectMake(0.0, 0.0, 100.0, 100.0)];
	if (self)
	{
		[self setOpaque:NO];
		annot = [_annot retain];
		pageSize = _pageSize;
		color = [[UIColor colorWithRed:0x44/255.0 green:0x44/255.0 blue:1.0 alpha:1.0] retain];
	}
	return self;
}

-(void) dealloc
{
	[annot release];
	[color release];
	[super dealloc];
}

- (void)drawRect:(CGRect)rect
{
	CGSize scale = fitPageToScreen(pageSize, self.bounds.size);
	CGContextRef cref = UIGraphicsGetCurrentContext();
	CGContextScaleCTM(cref, scale.width, scale.height);
	[color set];
	CGContextStrokeRect(cref, annot.rect);
}

@end
