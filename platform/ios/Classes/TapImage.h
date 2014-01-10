#import <UIKit/UIKit.h>

@interface TapImage : UIImageView
{
	id target;
	SEL action;
}
- (id)initWithResource:(NSString *)resource target:(id)obj action:(SEL)selector;
@end
