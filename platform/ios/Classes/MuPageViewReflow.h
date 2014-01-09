#import <UIKit/UIKit.h>
#import "MuDocRef.h"
#import "MuPageView.h"

@interface MuPageViewReflow : UIWebView <UIWebViewDelegate,MuPageView>
{
	int number;
	float scale;
}

-(id) initWithFrame:(CGRect)frame document:(MuDocRef *)aDoc page:(int)aNumber;

@end
