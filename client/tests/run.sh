#!/bin/bash

cd ../../server
rm -rf mboxes
rm -rf receipts
#echo "" > server.log
#python3 server.py &
#pid1=$!
#echo "server running"

#cd ../tests
#sleep 1
#python3 test.py &
#echo "testing..."

#trap ctrl_c INT
#function ctrl_c() {
#    sudo kill -9 $pid1
#    exit
#}

#cd ../server
#tail -f server.log