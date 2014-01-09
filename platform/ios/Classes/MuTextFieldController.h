#import <UIKit/UIKit.h>

@interface MuTextFieldController : UIViewController
{
	void (^okayBlock)(NSString *);
	NSString *initialText;
}
- (id)initWithText:(NSString *)text okayAction:(void (^)(NSString *))block;
@end
