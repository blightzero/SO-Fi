#!/bin/sh

# Set up and compile modules need for python backend.
# i.e. do the python C #define imports, compile the python modules
# and copy them to the right folder.

# Script has to be called from the SO-Fi folder as it uses the
# respective related paths.

set -e

echo "Setting up SO-Fi modules..."

make
make python-imports

cd pywpactrl && python setup.py build_ext -i && mv wpactrl.so ../

echo "SO-Fi python backend setup finished."
