#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface MuWord : NSObject
@property(retain) NSString *string;
@property(assign) CGRect rect;
+ (MuWord *) word;
- (void) appendChar:(unichar)c withRect:(CGRect)rect;
+ (void) selectFrom:(CGPoint)pt1 to:(CGPoint)pt2 fromWords:(NSArray *)words onStartLine:(void (^)(void))startBlock onWord:(void (^)(MuWord *))wordBlock onEndLine:(void (^)(void))endBLock;
@end
