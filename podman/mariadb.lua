Notify("Starting mariadb container...")
require("podman")({
	NAME = "mariadb",
	URL = "docker://docker.io/library/mariadb",
	TAG = "10.5",
	IP = "0.255.128.1",
	CPUS = "3",
	MEM = "1g",
})
