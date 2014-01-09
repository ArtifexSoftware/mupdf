#include "common.h"

@interface MuTextSelectView : UIView
{
	NSArray *words;
	CGSize pageSize;
	UIColor *color;
	CGPoint start;
	CGPoint end;
}
- (id) initWithWords:(NSArray *)_words pageSize:(CGSize)_pageSize;
- (NSArray *) selectionRects;
- (NSString *) selectedText;
@end
