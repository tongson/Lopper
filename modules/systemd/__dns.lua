local Corefile = [[
.:53 {
       bind 127.255.255.53
       bufsize 1232
       acl {
               allow net 127.0.0.0/8
               block
       }
       hosts /config/hosts {
               ttl 60
               fallthrough
       }
       loadbalance
       forward . /etc/resolv.conf {
               max_concurrent 1024
       }
       prometheus :9153
       errors
       log
}
]]
local crypto = require("crypto")
Corefile = crypto.base64_encode(Corefile)
return {
	volumes = {
		["coredns-config"] = {
			([[printf "%s" | base64 --decode > __MOUNTPOINT__/Corefile]]):format(Corefile),
		}
	},
unit = [==[
[Unit]
Description=coredns Container
Wants=network.target
After=network-online.target

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=on-failure
RestartSec=5
TimeoutStartSec=infinity
TimeoutStopSec=120
Type=forking
PIDFile=/run/podman-coredns.pid
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
ExecStartPre=-/usr/bin/podman stop -i coredns
ExecStartPre=-/usr/bin/podman rm -i -v -f coredns
ExecStop=/usr/bin/podman stop -t 12 coredns
ExecStopPost=-/usr/bin/podman rm -i -v -f coredns
ExecStart=/usr/bin/podman run --name coredns \
--security-opt seccomp=/etc/podman.seccomp/coredns.json \
--replace \
--network host \
--hostname coredns  \
--cap-drop all \
--cap-add net_bind_service \
--conmon-pidfile=/run/podman-coredns.pid \
-e "TZ=UTC" \
--volume coredns-config:/config \
--cpuset-cpus __CPUS__ \
--memory __MEM__ \
__ID__

[Install]
WantedBy=multi-user.target
]==],
}

