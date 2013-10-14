//
//  MuTextFieldController.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface MuTextFieldController : UIViewController
{
	void (^okayBlock)(NSString *);
	NSString *initialText;
}
@property (retain, nonatomic) IBOutlet UITextView *textView;
- (id)initWithText:(NSString *)text okayAction:(void (^)(NSString *))block;
- (IBAction)okayTapped:(id)sender;
- (IBAction)cancelTapped:(id)sender;
@end
