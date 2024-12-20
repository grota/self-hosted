#!/bin/bash

for dir in */; do
    if [[ "$dir" == "compose-snippets/" ]]; then
        continue
    fi
    if [[ "$dir" == "jackett/" ]]; then
        continue
    fi
    if [[ "$dir" == "recyclarr/" ]]; then
        continue
    fi

    echo "Entering directory: $dir"
    cd "$dir" || { echo "Failed to enter $dir"; continue; }

    if [ -f "compose.yaml" ]; then
        echo "Running 'docker compose up -d' in $dir"
        docker compose up -d
    else
        echo "No compose.yaml found in $dir, skipping."
    fi

    cd ..
done

echo "Script execution completed."

