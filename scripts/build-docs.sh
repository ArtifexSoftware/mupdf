#!/bin/bash
# Set up a 'venv' and run sphinx to build the docs!

python -m venv build/sphinx-venv
source build/sphinx-venv/bin/activate

pip install -r docs/requirements.txt

sphinx-build -d build/sphinx-doctrees docs build/docs 2>&1 \
	| sed '/WARNING: more than one target found for .any. cross-reference.*:doc:.*:js:class:/d'
