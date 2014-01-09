#import <UIKit/UIKit.h>

@interface MuInkView : UIView
{
	CGSize pageSize;
	NSMutableArray *curves;
	UIColor *color;
}

@property(readonly) NSArray *curves;

- (id) initWithPageSize:(CGSize)pageSize;

@end
