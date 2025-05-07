PDF Write Options
=================

These are the common options to functions that write PDF files.

decompress
	 decompress all streams (except compress-fonts/images)

compress
	 Compress all streams. Bi-level images are compressed with CCITT Fax and generic data is compressed with flate.

	 compress=flate
		Compress streams with Flate (default).

	 compress=brotli
		Compress streams with Brotli (WARNING: this is a proposed PDF feature)

compress-fonts
	 compress embedded fonts

compress-images
	 compress images

compress-effort=0|percentage
	 effort spent compressing, 0 is default, 100 is max effort

ascii
	 ASCII hex encode binary streams

pretty
	 pretty-print objects with indentation

labels
	 print object labels

linearize
	 optimize for web browsers (no longer supported!)

clean
	 pretty-print graphics commands in content streams

sanitize
	 sanitize graphics commands in content streams

garbage
	garbage collect unused objects

	garbage=compact
		 ... and compact cross reference table

	garbage=deduplicate
		 ... and remove duplicate objects

incremental
	 write changes as incremental update

objstms
	 use object streams and cross reference streams

appearance=yes|all
	 synthesize just missing, or all, annotation/widget apperance streams

continue-on-error
	 continue saving the document even if there is an error

decrypt
	 write unencrypted document

encrypt=rc4-40|rc4-128|aes-128|aes-256
	 write encrypted document

permissions=NUMBER
	 document permissions to grant when encrypting

user-password=PASSWORD
	 password required to read document

owner-password=PASSWORD
	 password required to edit document

regenerate-id
	 (default yes) regenerate document id
