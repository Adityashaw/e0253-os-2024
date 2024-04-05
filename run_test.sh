#!/bin/bash

# Function to run ./test and kill it after 3 seconds
run_test() {
    timeout 8 ./testcase -n 4 -t 1
}

# Trap Ctrl+C to exit the loop gracefully
trap ctrl_c INT

ctrl_c() {
    echo "Exiting..."
    exit 0
}

# Loop to run ./test repeatedly
while true; do
    run_test
    sleep 3.1
done

