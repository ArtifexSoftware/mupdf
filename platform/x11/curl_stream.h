#if !defined(CURL_STREAM_H) && defined(HAVE_CURL)

#define CURL_STREAM_H

fz_stream *fz_stream_from_curl(fz_context *ctx, char *url, void (*more_data)(void *,int), void *more_data_arg);

#endif
