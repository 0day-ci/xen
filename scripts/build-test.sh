#!/bin/sh

# Run command on every commit within the range specified. If no command is
# provided, use the default one to clean and build the whole tree.
#
# Cross-build is not yet supported.

set -e

if ! test -f xen/common/kernel.c; then
    echo "Please run this script from top-level directory"
    exit 1
fi

if test $# -lt 2 ; then
    echo "Usage: $0 <BASE> <TIP> [CMD]"
    exit 1
fi

status=`git status -s`
if test -n "$status"; then
    echo "Tree is dirty, aborted"
    exit 1
fi

if git branch | grep -q '^\*.\+detached at'; then
    echo "Detached HEAD, aborted"
    exit 1
fi

BASE=$1; shift
TIP=$1; shift
ORIG_BRANCH=`git rev-parse --abbrev-ref HEAD`

if ! git merge-base --is-ancestor $BASE $TIP; then
    echo "$BASE is not an ancestor of $TIP, aborted"
    exit 1
fi

git rev-list $BASE..$TIP | nl -ba | tac | \
while read num rev; do
    echo "Testing $num $rev"
    git checkout $rev
    if test $# -eq 0 ; then
        make -j4 distclean && ./configure && make -j4
    else
        "$@"
    fi
    echo
done

echo "Restoring original HEAD"
git checkout $ORIG_BRANCH
