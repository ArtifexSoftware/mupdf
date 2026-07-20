#!/bin/bash
#
# Describe the current checked out version of MuPDF.
#
# Compares the current git commit and branch with version.h to
# format a suitable version string.
#
# If we're on a tag, show that tag; otherwise show the version.h string with
# the current git commit SHA1.

SRC=$(grep 'FZ_VERSION ' include/mupdf/fitz/version.h | cut -d' ' -f3 | tr -d '"')
S=$(echo $SRC | cut -d. -f1,2)

TAG=$(git describe --tags)
T=$(echo $TAG | cut -d- -f1 | cut -d. -f1,2)

if test "$T" != "$S"
then
	if git symbolic-ref --quiet HEAD > /dev/null; then
		echo -n "$(git symbolic-ref HEAD | sed 's,refs/heads/,,') "
	else
		echo -n "DETACHED "
	fi

	# Without this "git diff-files" will still report recently
	# checked-in files as unstaged until you run "git status"
	git update-index --refresh > /dev/null

	echo "$(date -I) ($(git rev-parse --short HEAD)$(if ! git diff-index --quiet --cached HEAD --; then echo "+staged"; fi)$(if ! git diff-files --quiet; then echo "+unstaged"; fi))"
else
	echo $TAG
fi
