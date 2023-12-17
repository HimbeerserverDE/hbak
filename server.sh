#! /bin/sh

handle_connection() {
	read -r LINE
	echo "${LINE}"
}

export -f handle_connection

socat TCP6-LISTEN:45545,reuseaddr,fork,end-close system:'sh -c handle_connection'
