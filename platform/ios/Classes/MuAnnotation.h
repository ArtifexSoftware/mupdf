#include "common.h"
#include "mupdf/pdf.h"
#import <Foundation/Foundation.h>

@interface MuAnnotation : NSObject
-(instancetype) initFromAnnot:(fz_annot *)annot;
@property(readonly) int type;
@property(readonly) CGRect rect;
+(MuAnnotation *) annotFromAnnot:(fz_annot *)annot;
@end
