#include "common.h"

@interface MuTextSelectView : UIView
- (instancetype) initWithWords:(NSArray *)_words pageSize:(CGSize)_pageSize;
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSArray *selectionRects;
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSString *selectedText;
@end
