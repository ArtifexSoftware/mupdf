#import <UIKit/UIKit.h>
#import <MuDocRef.h>

@interface MuPrintPageRenderer : UIPrintPageRenderer
{
	MuDocRef *docRef;
}

-(id) initWithDocRef:(MuDocRef *) docRef;

@end
