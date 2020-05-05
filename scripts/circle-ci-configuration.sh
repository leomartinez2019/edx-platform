#!/usr/bin/env bash
###############################################################################
#
#   circle-ci-configuration.sh
#
###############################################################################

# From the sh(1) man page of FreeBSD:
# Exit immediately if any untested command fails. in non-interactive
# mode.  The exit status of a command is considered to be explicitly
# tested if the command is part of the list used to control an if,
# elif, while, or until; if the command is the left hand operand of
# an “&&” or “||” operator; or if the command is a pipeline preceded
# by the ! operator.  If a shell function is executed and its exit
# status is explicitly tested, all commands of the function are con‐
# sidered to be tested as well.
set -e

# Return status is that of the last command to fail in a
# piped command, or a zero if they all succeed.
set -o pipefail

EXIT=0

sleep $[ ( $RANDOM % 5 )  + 1 ]s

# Manually installing the mongo-3.2
apt-get update
apt-get install wget -y
wget -qO - https://www.mongodb.org/static/pgp/server-3.2.asc | sudo apt-key add -
echo "deb http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list

sudo apt-get update

cat requirements/system/ubuntu/apt-packages.txt | DEBIAN_FRONTEND=noninteractive xargs apt-get -yq install
apt-get install -y mongodb-org=3.2.21 mongodb-org-server=3.2.21 mongodb-org-shell=3.2.21 mongodb-org-mongos=3.2.21 mongodb-org-tools=3.2.21

service mongodb restart

mkdir -p downloads

DEBIAN_FRONTEND=noninteractive apt-get -yq install xvfb libasound2 libstartup-notification0



export NODEJS_FILE="downloads/nodejs_8.9.3-1nodesource1_amd64.deb"
if [ -f $NODEJS_FILE ]; then
   echo "File $NODEJS_FILE found."
else
   echo "Downloading nodejs_8.9.3-1nodesource1_amd64.deb."
   wget -O $NODEJS_FILE deb.nodesource.com/node_8.x/pool/main/n/nodejs/nodejs_8.9.3-1nodesource1_amd64.deb
fi
dpkg -i $NODEJS_FILE || DEBIAN_FRONTEND=noninteractive apt-get -fyq install



export FIREFOX_FILE="downloads/firefox-mozilla-build_61.0-0ubuntu1_amd64.deb"
if [ -f $FIREFOX_FILE ]; then
   echo "File $FIREFOX_FILE found."
else
   echo "Downloading firefox-mozilla-build_61.0-0ubuntu1_amd64.deb."
   wget -O $FIREFOX_FILE sourceforge.net/projects/ubuntuzilla/files/mozilla/apt/pool/main/f/firefox-mozilla-build/firefox-mozilla-build_61.0-0ubuntu1_amd64.deb
fi
dpkg -i $FIREFOX_FILE || DEBIAN_FRONTEND=noninteractive apt-get -fyq install
firefox --version

# To solve installation problems
apt-get install libsqlite3-dev -y
