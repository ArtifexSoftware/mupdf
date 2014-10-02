#import <UIKit/UIKit.h>

@interface MuInkView : UIView

@property(readonly) NSArray *curves;

- (id) initWithPageSize:(CGSize)pageSize;

@end
