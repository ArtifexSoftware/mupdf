#import <Foundation/Foundation.h>

@protocol MuDialogCreator <NSObject>
- (void) invokeTextDialog:(NSString *)aString okayAction:(void (^)(NSString *))block;
- (void) invokeChoiceDialog:(NSArray *)anArray okayAction:(void (^)(NSArray *))block;
@end
