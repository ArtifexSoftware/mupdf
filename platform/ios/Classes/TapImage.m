#import "TapImage.h"

static const NSTimeInterval TapDuration = 0.05;

@implementation TapImage

- (id)initWithResource:(NSString *)resource target:(id)targ action:(SEL)selector
{
	UIImage *image = [UIImage imageWithContentsOfFile:[[NSBundle mainBundle] pathForResource:resource ofType:@"png"]];
	if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 7.0)
		image = [image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
	self = [super initWithImage:image];
	if (self)
	{
		target = targ;
		action = selector;
		UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onTap)];
		[self addGestureRecognizer:tap];
		[tap release];
	}
	return self;
}

- (void) onTap
{
	[UIView animateWithDuration:TapDuration animations:^{
		self.backgroundColor = [UIColor darkGrayColor];
	} completion:^(BOOL finished) {
		[UIView animateWithDuration:TapDuration animations:^{
			self.backgroundColor = [UIColor clearColor];
		} completion:^(BOOL finished) {
			[target performSelector:action withObject:nil];
		}];
	}];
}

@end
