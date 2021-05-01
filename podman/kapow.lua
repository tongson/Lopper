Notify("Starting kapow container...")
require("podman")({
	NAME = "kapow",
	URL = "kapow",
	TAG = "0.7.0",
	IP = "0.255.80.1",
	CPUS = "2",
	SHARES = "256",
	MEM = "128m",
})
