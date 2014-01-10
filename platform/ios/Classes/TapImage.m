#import "TapImage.h"

@implementation TapImage

- (id)initWithResource:(NSString *)resource target:(id)targ action:(SEL)selector
{
	UIImage *image = [UIImage imageWithContentsOfFile:[[NSBundle mainBundle] pathForResource:resource ofType:@"png"]];
	self = [super initWithImage:image];
	if (self)
	{
		UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:targ action:selector];
		[self addGestureRecognizer:tap];
		[tap release];
	}
	return self;
}

@end
