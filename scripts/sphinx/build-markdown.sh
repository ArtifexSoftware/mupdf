#!/bin/bash

# Build a plain markdown version of the sphinx documentation,
# that can be further processed by pandoc to make a simple
# HTML version for the long term documentation archive.

OUT=build/docs/sphinx

python3 -m venv build/sphinx-venv
source build/sphinx-venv/bin/activate

pip install -r scripts/sphinx/requirements.txt

pip install sphinx_markdown_builder

sphinx-build \
	-j auto \
	-b markdown \
	-c scripts/sphinx \
	-d build/sphinx-doctrees \
	docs $OUT \
	2>&1 | sed '/WARNING: more than one target found for .any. cross-reference.*:doc:.*:js:class:/d'

# patch over bugs in sphinx_markdown_builder (wrong links to images)
sed -i -E -e 's,\(([/_A-Za-z0-9-]*\.(png|svg|jpg|webp))\),(../../../../\1),' $OUT/*/*/*/*.md
sed -i -E -e 's,\(([/_A-Za-z0-9-]*\.(png|svg|jpg|webp))\),(../../../\1),' $OUT/*/*/*.md
sed -i -E -e 's,\(([/_A-Za-z0-9-]*\.(png|svg|jpg|webp))\),(../../\1),' $OUT/*/*.md
sed -i -E -e 's,\(([/_A-Za-z0-9-]*\.(png|svg|jpg|webp))\),(../\1),' $OUT/*.md

# patch over bugs in sphinx_markdown_builder (no blank between blockquote and list after it)
perl -i -0 -pe 's/(>.*\n)-/\1\n-/g' $(find $OUT -name '*.md')

# adjust header levels in root document
sed -i -e '/Logo/,$s/^# /## /' $OUT/index.md
