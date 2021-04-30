return {
	volumes = {
		["kapow-src"] = {
			"rsync -Wa kapow-src/ __MOUNTPOINT__",
		}
	},
	ports = {
		"60080"
	},
	ip = "0.255.80.1",
unit = [==[
[Unit]
Description=kapow Container
Wants=network.target
After=network-online.target

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=on-failure
RestartSec=5
Type=notify
NotifyAccess=all
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes
LockPersonality=yes
NoNewPrivileges=yes
RemoveIPC=yes
DevicePolicy=closed
PrivateTmp=yes
PrivateNetwork=false
ProtectKernelModules=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelLogs=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
#PrivateDevices=yes
RestrictAddressFamilies=AF_INET
ExecStart=/usr/bin/podman run --name kapow \
--security-opt seccomp=/etc/podman.seccomp/kapow.json \
--rm \
--replace \
--network host \
--hostname kapow  \
--cap-drop all \
--sdnotify conmon \
--conmon-pidfile=/run/podman-kapow.pid \
-e "TZ=UTC" \
--volume kapow-src:/src \
--cpu-shares __SHARES \
--cpuset-cpus __CPUS__ \
--memory __MEM__ \
__ID__  --debug --control-reachable-addr '__IP__:60081' --bind __IP__:60080 --control-bind __IP__:60081 --data-bind __IP__:60082 /src/index.pow

[Install]
WantedBy=multi-user.target
]==],
}
