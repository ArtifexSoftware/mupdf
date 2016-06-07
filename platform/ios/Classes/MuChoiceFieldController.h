#import <UIKit/UIKit.h>

@interface MuChoiceFieldController : UIViewController<UIPickerViewDataSource, UIPickerViewDelegate>
- (instancetype)initWithChoices:(NSArray *)choices okayAction:(void (^)(NSArray *))block;
@end
