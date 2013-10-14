//
//  MuChoiceFieldController.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface MuChoiceFieldController : UIViewController<UIPickerViewDataSource, UIPickerViewDelegate>
{
	void (^okayBlock)(NSArray *);
	NSArray *choices;
	int selected;
}
@property (retain, nonatomic) IBOutlet UIPickerView *picker;
- (id)initWithChoices:(NSArray *)choices okayAction:(void (^)(NSArray *))block;
- (IBAction)okayTapped:(id)sender;
- (IBAction)cancelTapped:(id)sender;
@end
