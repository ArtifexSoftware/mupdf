#import <UIKit/UIKit.h>

@interface MuInkView : UIView

@property(readonly) NSArray *curves;

- (instancetype) initWithPageSize:(CGSize)pageSize;

@end
