#!/bin/bash

# Bash: This is the first part up to the first `.': ${tgt%%.*}

# This script copies the master init script file to the init directory and
# renames them to the short name of the server
# So: h.example.edu -> /etc/init/go-balance.hoek.conf
# The actual server specific (here: hoek) config will be in a .override file:
# http://upstart.ubuntu.com/cookbook/#override-files

# You can run this script relatively safely since it will use "install" and
# create a backup files instead of just overriding them

# You are expected to create and install the .override files!

for i in "h.example.edu" \
         "x.example.edu" \
         "y.example.edu"
do 
  short_name=${i%%.*}
  install --mode=0644 --backup=numbered go-balance-master.conf /etc/init/go-balance-$short_name.conf
  echo "Installed /etc/init/go-balance-$short_name.conf"
done;


