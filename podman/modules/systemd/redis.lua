-- Required by Docker Hub Alpine container
return {
	capabilities = { "chown", "setuid", "setgid" },
}
