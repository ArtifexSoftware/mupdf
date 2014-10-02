#import <UIKit/UIKit.h>

@interface MuTextFieldController : UIViewController
- (id)initWithText:(NSString *)text okayAction:(void (^)(NSString *))block;
@end
