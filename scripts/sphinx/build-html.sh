#!/bin/bash
# Set up a 'venv' and run sphinx to build the docs!

python3 -m venv build/sphinx-venv
source build/sphinx-venv/bin/activate

pip install -r scripts/sphinx/requirements.txt

sphinx-build \
	-j auto \
	-b html \
	-c scripts/sphinx \
	-d build/sphinx-doctrees \
	docs build/sphinx-html \
	2>&1 | sed '/WARNING: more than one target found for .any. cross-reference.*:doc:.*:js:class:/d'
