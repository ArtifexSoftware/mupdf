#include "common.h"
#import "MuTextSelectView.h"
#import "MuWord.h"

@implementation MuTextSelectView
{
	NSArray *words;
	CGSize pageSize;
	UIColor *color;
	CGPoint start;
	CGPoint end;
}

- (id) initWithWords:(NSArray *)_words pageSize:(CGSize)_pageSize
{
	self = [super initWithFrame:CGRectMake(0,0,100,100)];
	if (self)
	{
		[self setOpaque:NO];
		words = [_words retain];
		pageSize = _pageSize;
		color = [[UIColor colorWithRed:0x25/255.0 green:0x72/255.0 blue:0xAC/255.0 alpha:0.5] retain];
		UIPanGestureRecognizer *rec = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onDrag:)];
		[self addGestureRecognizer:rec];
		[rec release];
	}
	return self;
}

-(void) dealloc
{
	[words release];
	[color release];
	[super dealloc];
}

- (NSArray *) selectionRects
{
	NSMutableArray *arr = [NSMutableArray array];
	__block CGRect r;

	[MuWord selectFrom:start to:end fromWords:words
		onStartLine:^{
			r = CGRectNull;
		} onWord:^(MuWord *w) {
			r = CGRectUnion(r, w.rect);
		} onEndLine:^{
			if (!CGRectIsNull(r))
				[arr addObject:[NSValue valueWithCGRect:r]];
		}];

	return arr;
}

- (NSString *) selectedText
{
	__block NSMutableString *text = [NSMutableString string];
	__block NSMutableString *line;

	[MuWord selectFrom:start to:end fromWords:words
		onStartLine:^{
			line = [NSMutableString string];
		} onWord:^(MuWord *w) {
			if (line.length > 0)
				[line appendString:@" "];
			[line appendString:w.string];
		} onEndLine:^{
			if (text.length > 0)
				[text appendString:@"\n"];
			[text appendString:line];
		}];

	return text;
}

-(void) onDrag:(UIPanGestureRecognizer *)rec
{
	CGSize scale = fitPageToScreen(pageSize, self.bounds.size);
	CGPoint p = [rec locationInView:self];
	p.x /= scale.width;
	p.y /= scale.height;

	if (rec.state == UIGestureRecognizerStateBegan)
		start = p;

	end = p;

	[self setNeedsDisplay];
}

- (void) drawRect:(CGRect)rect
{
	CGSize scale = fitPageToScreen(pageSize, self.bounds.size);
	CGContextRef cref = UIGraphicsGetCurrentContext();
	CGContextScaleCTM(cref, scale.width, scale.height);
	__block CGRect r;

	[color set];

	[MuWord selectFrom:start to:end fromWords:words
		onStartLine:^{
			r = CGRectNull;
		} onWord:^(MuWord *w) {
			r = CGRectUnion(r, w.rect);
		} onEndLine:^{
			if (!CGRectIsNull(r))
				UIRectFill(r);
		}];
}

@end
