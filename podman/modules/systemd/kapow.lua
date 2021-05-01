return {
	volumes = {
		["kapow-src"] = {
			"rsync -Wa kapow-src/ __MOUNTPOINT__",
		}
	},
	mounts = {
		["kapow-src"] = "/src",
	},
	ports = {
		"60080",
	},
	ip = "0.255.80.1",
	cmd = "--debug --control-reachable-addr '__IP__:60081' --bind __IP__:60080 --control-bind __IP__:60081 --data-bind __IP__:60082 /src/index.pow",
}
