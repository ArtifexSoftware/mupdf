#import <UIKit/UIKit.h>

@interface MuChoiceFieldController : UIViewController<UIPickerViewDataSource, UIPickerViewDelegate>
{
	void (^okayBlock)(NSArray *);
	NSArray *choices;
	int selected;
}
- (id)initWithChoices:(NSArray *)choices okayAction:(void (^)(NSArray *))block;
@end
