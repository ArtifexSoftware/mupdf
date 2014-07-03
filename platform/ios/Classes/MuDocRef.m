#include "common.h"
#include "mupdf/pdf.h"
#import "MuDocRef.h"

@implementation MuDocRef

-(id) initWithFilename:(char *)aFilename;
{
	self = [super init];
	if (self)
	{
		dispatch_sync(queue, ^{});

		fz_var(self);

		fz_try(ctx)
		{
			doc = fz_open_document(ctx, aFilename);
			if (!doc)
			{
				[self release];
				self = nil;
			}
			else
			{
				pdf_document *idoc = pdf_specifics(doc);
				if (idoc) pdf_enable_js(idoc);
				interactive = (idoc != NULL) && (pdf_crypt_version(idoc) == 0);
			}
		}
		fz_catch(ctx)
		{
			if (doc != NULL)
				fz_close_document(doc);
			[self release];
			self = nil;
		}
	}
	return self;
}

-(void) dealloc
{
	__block fz_document *block_doc = doc;
	dispatch_async(queue, ^{
		fz_close_document(block_doc);
	});
	[super dealloc];
}

@end
