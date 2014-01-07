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
- (id)initWithChoices:(NSArray *)choices okayAction:(void (^)(NSArray *))block;
@end
