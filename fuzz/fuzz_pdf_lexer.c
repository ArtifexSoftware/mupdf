/*
 * Fuzzer for MuPDF PDF lexer - low-level token parsing
 * This targets the core PDF parsing infrastructure
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mupdf/fitz.h>
#include <mupdf/pdf.h>

#define MAX_INPUT_SIZE (256 * 1024)  /* 256KB limit */

static fz_context *ctx = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_stream *stream = NULL;
	pdf_lexbuf lexbuf;
	pdf_token tok;
	int token_count = 0;
	const int max_tokens = 10000;  /* Prevent infinite loops */

	if (size == 0 || size > MAX_INPUT_SIZE)
		return 0;

	memset(&lexbuf, 0, sizeof(lexbuf));

	fz_var(stream);

	fz_try(ctx)
	{
		pdf_lexbuf_init(ctx, &lexbuf, PDF_LEXBUF_SMALL);
		stream = fz_open_memory(ctx, data, size);

		/* Lex all tokens from the input */
		do {
			tok = pdf_lex(ctx, stream, &lexbuf);
			token_count++;
		} while (tok != PDF_TOK_EOF && tok != PDF_TOK_ERROR && token_count < max_tokens);
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stream);
		pdf_lexbuf_fin(ctx, &lexbuf);
	}
	fz_catch(ctx)
	{
		/* Ignore errors - we're fuzzing */
	}

	return 0;
}
