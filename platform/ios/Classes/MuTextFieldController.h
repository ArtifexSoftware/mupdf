#import <UIKit/UIKit.h>

@interface MuTextFieldController : UIViewController
- (instancetype)initWithText:(NSString *)text okayAction:(void (^)(NSString *))block;
@end
