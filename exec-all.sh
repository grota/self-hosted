#!/bin/bash

usage() {
    echo "Usage: $0 <command...> [--dirs dir1 dir2 ...]"
    exit 1
}

# Initialize variables
dirs=()
command=()
parsing_dirs=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dirs)
            parsing_dirs=true
            shift
            ;;
        *)
            if [[ $parsing_dirs == true ]]; then
                if [[ $1 == -* ]]; then
                    parsing_dirs=false
                else
                    dirs+=("$1")
                    shift
                    continue
                fi
            fi
            command+=("$1")
            shift
            ;;
    esac
done

# Validate command
if [ ${#command[@]} -eq 0 ]; then
    echo "Error: No command specified"
    usage
fi

# Use specified directories or find all subdirectories
if [ ${#dirs[@]} -eq 0 ]; then
    dirs=($(find . -maxdepth 1 -type d -not -name "." -not -name "compose-snippets" -not -name "recyclarr" -not -name '.git'))
fi

# Process each directory
for dir in "${dirs[@]}"; do
    dir="${dir%/}"  # Remove trailing slash
    echo "Entering directory: $dir"
    cd "$dir" || { echo "Failed to enter $dir"; continue; }

    if [ "${command[0]}" == "docker" ] && [ "${command[1]}" == "compose" ] && [ ! -f "compose.yaml" ]; then
        echo "Error: 'docker compose' command detected but not compose.yaml found."
        cd ..
        continue
    fi
    echo "Running '${command[*]}' in $dir"
    "${command[@]}"

    cd ..
done

echo "Script execution completed."
