#!/usr/bin/env sh

set -e

# Function to handle signals
handle_signal() {
    echo "Received signal, shutting down..."
    exit 0
}

# This allows the script to check for signals every second
safe_sleep() {
  i=1
  while [ $i -lt "$1" ]; do
    i=$((i + 1))
    sleep 1
  done
}

# Trap signals
trap handle_signal TERM INT

# Function to perform ping with retry
ping_with_retry() {
    ping -c 2 google.com >/dev/null 2>&1
    return $?
}

# Main loop
while true; do
    if ping_with_retry; then
        echo "Ping successful, sleeping for 10 minutes"
        safe_sleep 600
    else
        # 2, 5, 10 minutes
        for interval in 120 300 600; do
            echo "Ping failed, sleeping $interval seconds and trying again."
            safe_sleep $interval
            if ping_with_retry; then
                echo "Ping successful after retry."
                continue 2
            fi
        done
        echo "All retries failed, restarting router"
        npx playwright test --project=firefox --quiet --reporter=list reboot-router
        # 20 minutes
        safe_sleep 1200
    fi
done
