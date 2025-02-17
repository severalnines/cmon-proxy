#!/bin/sh
set -x  # Enable debug mode to print commands

echo "Checking binary locations and permissions:"
ls -la /usr/local/bin/ccmgr*
echo "PATH=$PATH"

if [ ! -z "$INIT_LOCAL_CMON" ]; then
    echo "Initializing local CMON configuration..."
    
    INIT_CMD="/usr/local/bin/ccmgradm init --basedir=/usr/share/ccmgr --local-cmon"
    
    if [ ! -z "$CMON_PROXY_PORT" ]; then
        INIT_CMD="$INIT_CMD -p $CMON_PROXY_PORT"
    fi
    
    if [ ! -z "$WEBAPP_PATH" ]; then
        INIT_CMD="$INIT_CMD -f $WEBAPP_PATH"
    fi

    if [ ! -z "$CMON_URL" ]; then
        INIT_CMD="$INIT_CMD -u $CMON_URL"
    fi
    
    echo "Executing command: $INIT_CMD"
    sh -c "$INIT_CMD"
    
    RESULT=$?
    echo "Command exit code: $RESULT"
fi

exec /usr/local/bin/ccmgr --basedir=/usr/share/ccmgr/