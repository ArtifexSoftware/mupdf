#import <UIKit/UIKit.h>

#import "MuDocRef.h"

@interface MuPrintPageRenderer : UIPrintPageRenderer

-(instancetype) initWithDocRef:(MuDocRef *) docRef;

@end
