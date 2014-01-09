#import <UIKit/UIKit.h>
#import "MuAnnotation.h"

@interface MuAnnotSelectView : UIView
{
	MuAnnotation *annot;
	CGSize pageSize;
	UIColor *color;
}
- (id) initWithAnnot:(MuAnnotation *)_annot pageSize:(CGSize)_pageSize;
@end
