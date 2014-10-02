#import <UIKit/UIKit.h>

@interface MuChoiceFieldController : UIViewController<UIPickerViewDataSource, UIPickerViewDelegate>
- (id)initWithChoices:(NSArray *)choices okayAction:(void (^)(NSArray *))block;
@end
