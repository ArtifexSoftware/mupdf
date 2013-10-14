//
//  MuTextFieldController.m
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import "MuTextFieldController.h"

@interface MuTextFieldController ()
@end

@implementation MuTextFieldController

-(id)initWithText:(NSString *)text okayAction:(void (^)(NSString *))block
{
	self = [super initWithNibName:@"MuTextFieldController" bundle:nil];
	if (self)
	{
		okayBlock = Block_copy(block);
		initialText = [text retain];
	}
	return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
	_textView.text = initialText;
    // Do any additional setup after loading the view from its nib.
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)dealloc
{
	[okayBlock release];
	[initialText release];
    [_textView release];
    [super dealloc];
}

- (IBAction)okayTapped:(id)sender
{
	okayBlock(_textView.text);
	[self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)cancelTapped:(id)sender
{
	[self dismissViewControllerAnimated:YES completion:nil];
}

@end
