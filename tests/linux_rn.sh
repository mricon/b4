#!/bin/sh
#
# b4 rn examples to be run from linux source tree
#
# Usage:
#
#  T=$PWD/tests/
#  cd ~/src/linux
#  $T/linux_rn.sh -d 2>rn.log
#  $T/linux_rn.sh -d $T/xfs-5.10..5.17.in -p linux-xfs
#

if ! (git rev-parse v2.6.12-rc2  2> /dev/null | \
	grep -q 9e734775f7c22d2f89943ad6c745571f1930105f); then
	echo "Please run this test from a linux source tree"
	exit 1
fi

RNMBX=/tmp/linux_rn.mbx
RNOUT=/tmp/linux_rn.out

if [ "$1" = "-d" ]; then
	RNDEBUG=$1
	shift
fi
RNOPTS="$*"

git_fixes_rn()
{
	local descr="$1"
	local range="$2"
	local path="$3"

	echo "---"
	echo "GIT log - $descr"
	echo "---"
	git log -p --grep Fixes: --pretty=email $range -- $path | \
		b4 $RNDEBUG rn $RNOPTS -m -
}

pr_tracker_rn()
{
	local descr="$1"
	local msgid="$2"

	rm -rf $RNMBX $RNOUT

	echo "---"
	echo "PR tracker - $descr"
	echo "---"
	b4 $RNDEBUG pr -e -o $RNMBX "$msgid"
	b4 $RNDEBUG rn $RNOPTS -m $RNMBX -o $RNOUT
	cat $RNOUT
}


# Process PR list from input file
if [ -f "$1" ]; then
	PRFILE="$1"
	shift
	RNOPTS="$*"
	cat "$PRFILE" | while read pr name; do
		echo "Writing release notes of $pr to $name.out..."
		>"$name".out 2>"$name".log </dev/null \
			pr_tracker_rn "$name" "$pr"
	done
	exit
fi

git_fixes_rn "series with fix patches for subsystem" \
	v5.13..v5.14 fs/xfs

pr_tracker_rn "patches not posted" \
	164374837231.6282.14818932060276777076.pr-tracker-bot@kernel.org

pr_tracker_rn "individual patch posted" \
	164590250253.22829.8421551678388979175.pr-tracker-bot@kernel.org

pr_tracker_rn "patch series posted" \
	164408216661.7836.4930013315804213982.pr-tracker-bot@kernel.org

pr_tracker_rn "patch series including partial reroll" \
	164817214223.9489.12483808836905609419.pr-tracker-bot@kernel.org

pr_tracker_rn "many patch series" \
	163060423908.29568.14182828511329643634.pr-tracker-bot@kernel.org
