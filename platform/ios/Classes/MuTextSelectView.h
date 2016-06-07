#include "common.h"

@interface MuTextSelectView : UIView
- (instancetype) initWithWords:(NSArray *)_words pageSize:(CGSize)_pageSize;
- (NSArray *) selectionRects;
- (NSString *) selectedText;
@end
