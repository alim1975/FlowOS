#!/bin/sh
set -e
echo "Installing m4..."
libtoolize --force
echo "Installing missing files and creating configuration script..."
autoreconf --install || exit 1


