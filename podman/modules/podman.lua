local DSL = "podman"
local DEBUGGING = false --> Toggle DEBUG() calls
local HOST = false --> Toggle --network host mode
local domain = os.getenv("PODMAN_DOMAIN") or "host.local"
local creds = os.getenv("PODMAN_CREDS")
local systemd_unit_start = {
	[===[
[Unit]
Description=__CNAME__ Container
Wants=network.target
After=network-online.target

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
EnvironmentFile=-/etc/podman.env/%p
EnvironmentFile=-/etc/podman.env/%p@%i
Restart=on-failure
RestartSec=5
Type=notify
NotifyAccess=all
KillMode=mixed
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes
LockPersonality=yes
NoNewPrivileges=yes
RemoveIPC=yes
DevicePolicy=closed
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=~AF_INET6
ExecStopPost=/usr/bin/podman rm -i -v -f __CNAME__
ExecStart=/usr/bin/podman run --name __CNAME__ \
--security-opt seccomp=/etc/podman.seccomp/__CNAME__.json \
--security-opt apparmor=unconfined \
--security-opt label=disable \
--no-hosts \
--rm \
--replace \
--sdnotify conmon \
--network __NETWORK__ \
--hostname __NAME__ \
--cpu-shares __SHARES__ \
--cpuset-cpus __CPUS__ \
--memory __MEM__ \
--cap-drop all \]===],
}
-- Last line in systemd_unit[1] is correct.
local schema = {
	service_ip = "/%s/ip", --> string
	service_ports = "/%s/ports", --> list{string}
}
fs.mkdir("/etc/podman.etcdb")
local bitcask = require("bitcask")
local kv_running = bitcask.open("/etc/podman.etcdb/running")
local kv_service = bitcask.open("/etc/podman.etcdb/service")
local lopper = require("lopper")
local json = require("json")
local util = require("util")
local OK = function(msg, tbl)
	tbl._module = DSL
	return lopper.ok(msg, tbl)
end
local WARN = function(msg, tbl)
	tbl._module = DSL
	return lopper.warn(msg, tbl)
end
local DEBUG = function(msg, tbl)
	if DEBUGGING then
		tbl._module = DSL
		return lopper.debug(msg, tbl)
	end
end
local ASSERT = function(ret, msg, tbl)
	if ret == nil then
		tbl._module = DSL
		kv_running:close()
		kv_service:close()
		return lopper.panic(msg, tbl)
	end
end
local podman = exec.ctx("podman")
local get_id = function(n)
	local try = util.retry_f(podman)
	local r, so, se = try({
			"inspect",
			"--format",
			"json",
			n,
		})
	ASSERT(r, "BUG? Unable to find container.", {
		fn = "get_id()",
		stdout = so,
		stderr = se,
		command = "podman inspect",
		name = n,
	})
	local t = json.decode(so)
	return t[1]["Id"]
end
local get_volume = function(n)
	local ret, so, se = podman({
		"volume",
		"inspect",
		"--all",
	})
	ASSERT(ret, "No such volume or failure listing volumes.", {
		fn = "get_volume()",
		command = "volume inspect",
		stdout = so,
		stderr = se,
	})
	local j = json.decode(so)
	local found = {}
	if n then
		for _, v in ipairs(j) do
			if v.Name == n then
				return v.Mountpoint
			end
		end
		return nil
	else
		for _, v in ipairs(j) do
			found[v.Name] = v.Mountpoint
		end
		return found
	end
end
local volume = function(vt)
	local found = get_volume()
	for x, y in pairs(vt) do
		if not found[x] then
			local ret, so, se = podman({ "volume", "create", x })
			ASSERT(ret, "Host problem? Unable to create volume.", {
				fn = "volume()",
				command = "volume create",
				stdout = so,
				stderr = se,
			})
		end
		local mountpoint = get_volume(x)
		local sh = exec.ctx("sh")
		if type(y) == "table" then
			for _, cmd in ipairs(y) do
				local ret, so, se = sh({ "-c", cmd:gsub("__MOUNTPOINT__", mountpoint) })
				ASSERT(ret, "Failure executing volume command in systemd module.", {
					fn = "volume()",
					command = "volume ls",
					stdout = so,
					stderr = se,
				})
			end
		end
	end
end
local update_hosts = function()
	local running = kv_running:keys()
	local dns_config = get_volume("sys_dns-config")
	local hosts = {}
	for _, srv in ipairs(running) do
		if srv ~= "sys_dns" then
			local ip = kv_service:get(schema.service_ip:format(srv))
			hosts[#hosts + 1] = ("%s %s.%s %s"):format(ip, srv, domain, srv)
		end
	end
	hosts[#hosts + 1] = ""
	local hosts_file = table.concat(hosts, "\n")
	ASSERT(
		fs.write(dns_config .. "/hosts", hosts_file),
		"Unable to write system HOSTS file",
		{
			fn = "update_hosts()",
		}
	)
end
local Reserve_IDMAP = function(id)
	id = id or lopper.id
	local n = 2001234560
	local max = 2147483647
	local kv_idmap = bitcask.open("/etc/podman.etcdb/idmap")
	local key, ok
	repeat
		key = tostring(n)
		if not kv_idmap:has(key) then
			ok = kv_idmap:put(key, id)
		else
			n = n + 65537
		end
	until ok or n > max
	kv_idmap:close()
	ASSERT((n > max), "Reached maximum possible allocation. Clean up allocation database.", {
		fn = "reserve_idmap()",
		idmap = tostring(n),
	})
	OK("Reserved idmap allocation.", {
		range = key .. "-" .. tostring(n+65536),
		mark = id,
	})
	return key
end
local Release_IDMAP = function(key)
	local n = tonumber(key)
	local kv_idmap = bitcask.open("/etc/podman.etcdb/idmap")
	local r = kv_idmap:delete(key)
	kv_idmap:close()
	OK("Released idmap allocation.", {
		range = key .. "-" .. tostring(n+65536),
	})
	return r
end
local Running = function(direct)
	if not direct then
		return kv_running:keys()
	end
	-- Not from the etcdb but directly from podman
	local r, so, se = podman({ "ps", "-a", "--format", "json" })
	ASSERT(r, "Failure running podman command.", {
		fn = "running()",
		command = "podman ps",
		stdout = so,
		stderr = se,
	})
	local ret = json.decode(so)
	local names = {}
	for _, c in ipairs(ret) do
		if c["State"] == "running" then
			for _, n in ipairs(c["Names"]) do
				names[#names + 1] = n
			end
		end
	end
	return names
end
local Ports = function(srv)
	-- From etcdb
	local ports = kv_service:get(schema.service_ports:format(srv))
	local ret = json.decode(ports)
	ASSERT((type(ret) == "table"), "BUG? The etcdb path did not return a valid value.", {
		returned = ports,
		decoded = ret,
	})
end
local Get_Volume = get_volume
local stop = function(T)
	-- Does removal from kv_running etcdb and updates dns hosts.
	local c = T.reg.cname
	local systemctl = exec.ctx("systemctl")
	local so, se
	systemctl({ "disable", "--no-block", "--now", c })
	local is_inactive = function()
		_, so, se = systemctl({ "is-active", c })
		if so == "inactive\n" then
			return true
		else
			return nil, so, se
		end
	end
	local cmd = util.retry_f(is_inactive, 10)
	ASSERT(cmd(), "Failed stopping container. Still up.", {
		fn = "stop()",
		command = "systemctl is-active",
		name = c,
		stdout = so,
		stderr = se,
	})
	if HOST then
		if kv_running:has(c) then
			local try = util.retry_f(kv_running.delete)
			local deleted = try(kv_running, c)
			kv_running:close()
			ASSERT(deleted, "Host problem? Unable to remove container from etcdb/running.", {
				fn = "stop()",
				name = c,
			})
		end
		update_hosts()
	end
	OK("Stopped container(service).", {
		name = c,
	})
end
local start = function(T, stats)
	local c = T.reg.cname
	fs.mkdir("/var/log/podman") -- Checked in the next mkdir()
	local logdir = "/var/log/podman/" .. lopper.id
	if not fs.isdir(logdir) then
		ASSERT(fs.mkdir(logdir), "BUG? Unable to create logging directory.", {
			fn = "start()",
			directory = logdir,
		})
	end
	local journalctl = exec.ctx("journalctl")
	local cursor
	do
		local r, so, se = journalctl({"-u", c, "-o", "json", "-n", "1"})
		ASSERT(r, "BUG? Unable to get cursor from journalctl.", {
			name = c,
			fn = "start()",
			command = "journalctl",
			stdout = so,
			stderr = se,
		})
		local t = json.decode(so)
		if type(t) == "table" then
			cursor = t["__CURSOR"]
		end
	end

	local systemctl = exec.ctx("systemctl")
	local so, se
	systemctl({"daemon-reload"})
	systemctl({ "start", c })
	local is_active = function()
		_, so, se = systemctl({ "is-active", c })
		if so == "active\n" then
			return true
		else
			return nil, so, se
		end
	end
	local data
	if not stats then
		local cmd = util.retry_f(is_active, 10)
		ASSERT(cmd(), "Failed starting container. Check the unit journal.", {
			fn = "start()",
			command = "systemctl is-active",
			name = c,
			stdout = so,
			stderr = se,
		})
		data = { name = c }
	else
		repeat
		until is_active()
		local s = {
			cpu = {},
			mem = {},
			pids = {},
		}
		local x, y, z, pids
		local r, jo
		r, jo = podman({
				"stats",
				"--format",
				"json",
				"--no-stream",
				c,
			})
		do
			local tt = 0
			repeat
				tt = tt + 1
				x = json.decode(jo)
			until type(x) == "table" or tt == 10
			if tt == 10 then
				ASSERT(nil, "BUG? Did not return a valid output.", {
					fn = "start()",
					name = c,
					command = "podman stats",
				})
			end
		end
		while r and is_active() do
			x = json.decode(jo)
			if y ~= x[1]["cpu_percent"] then
				y = x[1]["cpu_percent"]
				s.cpu[#s.cpu+1]= y
			end
			if z ~= x[1]["mem_percent"] then 
				z = x[1]["mem_percent"]
				s.mem[#s.mem+1]= z
			end
			if pids ~= x[1]["pids"] then 
				pids = x[1]["pids"]
				s.pids[#s.pids+1]= pids
			end
			r, jo = podman({
				"stats",
				"--format",
				"json",
				"--no-stream",
				c,
			})
			os.sleep(stats)
		end
		data = {
			name = c,
			cpu = s.cpu,
			mem = s.mem,
			pids = s.pids,
		}
	end
	do
		local jargs = {"-o", "json-pretty", "-u", c}
		if cursor then
			jargs[#jargs+1] = ("--after-cursor=%s"):format(cursor)
		end
		local _, go = journalctl(jargs)
		local _, to = systemctl({"status", "-o", "json-pretty", c})
		--> No error checking, we do not want to interfere with a finished run.
		fs.write(("%s/%s.journal.json"):format(logdir, c), go)
		fs.write(("%s/%s.status.json"):format(logdir, c), to)
		fs.write(("%s/%s.output.json"):format(logdir, c), json.encode(data))
	end
	OK("Started container(service).", data)
end
local podman_interpolate = function(A)
	local systemctl = exec.ctx("systemctl")
	if A.param.NETWORK == "host" then
		systemctl({
			"disable",
			"--no-block",
			"--now",
			("%s.service"):format(A.param.NAME),
		})
	end
	local fname
	if A.param.NETWORK == "host" then
		fname = ("/etc/systemd/system/%s.service"):format(A.param.NAME)
	elseif A.param.NETWORK == "private" then
		fname = ("/etc/systemd/system/%s.pod.service"):format(A.param.NAME)
	else
		fname = ("/etc/systemd/system/%s.service"):format(A.reg.cname)
	end
	local unit, changed
	if not A.param.ROOT then
		unit, changed = A.reg.unit:gsub("__ID__", A.reg.id)
		-- Should only match once.
		ASSERT((changed == 1), "Unable to interpolate image ID.", {
			fn = "podman_interpolate() -> string.gsub()",
			changed = false,
			to = A.reg.id,
		})
	else
		unit = A.reg.unit
	end
	unit, changed = unit:gsub("__NAME__", A.param.NAME)
	ASSERT((changed > 1), "Unable to interpolate name.", {
		fn = "podman_interpolate() -> string.gsub()",
		changed = false,
		to = A.param.NAME,
	})
	unit, changed = unit:gsub("__CNAME__", A.reg.cname)
	ASSERT((changed == 4), "Unable to interpolate container name.", {
		fn = "podman_interpolate() -> string.gsub()",
		changed = false,
		to = A.reg.name,
	})
	if unit:contains("__IP__") then
		unit, changed = unit:gsub("__IP__", A.param.IP)
		ASSERT((changed >= 1), "Unable to interpolate IP.", {
			fn = "podman_interpolate() -> string.gsub()",
			changed = false,
			to = A.param.IP,
		})
	end
	unit, changed = unit:gsub("__CPUS__", A.param.CPUS)
	-- Should only match once.
	ASSERT((changed == 1), "Unable to interpolate --cpuset-cpus.", {
		fn = "podman_interpolate() -> string.gsub()",
		changed = false,
		to = A.param.CPUS,
	})
	unit, changed = unit:gsub("__MEM__", A.param.MEM)
	-- Should only match once.
	ASSERT((changed == 1), "Unable to interpolate --memory.", {
		fn = "podman_interpolate() -> string.gsub()",
		changed = false,
		to = A.param.MEM,
	})
	unit, changed = unit:gsub("__SHARES__", A.param.SHARES)
	-- Should only match once.
	ASSERT((changed == 1), "Unable to interpolate --cpu-shares.", {
		fn = "podman_interpolate() -> string.gsub()",
		changed = false,
		to = A.param.SHARES,
	})
	unit, changed = unit:gsub("__NETWORK__", A.reg.network)
	-- Should only match once.
	ASSERT((changed == 1), "Unable to interpolate --network.", {
		fn = "podman_interpolate() -> string.gsub()",
		changed = false,
		to = A.reg.network,
	})
	ASSERT(fs.write(fname, unit), "Unable to write unit.", {
		fn = "podman_interpolate() -> fs.write()",
		file = fname,
	})
end
local id = function(u, t)
	local r, so, se = podman({
		"images",
		"--format",
		"json",
	})
	ASSERT(r, "Host problem? Unable to list images.", {
		fn = "id()",
		command = "podman images",
		stdout = so,
		stderr = se,
	})
	local j = json.decode(so)
	_, u = util.path_split(u)
	local name = ("%s:%s"):format(u, t)
	for i = 1, #j do
		if table.find(j[i].Names, name) then
			return j[i].Id
		end
	end
	return nil, "Container image not found."
end
local pull = function(u, t)
	local pt = {
		"pull",
		"--tls-verify",
		("%s:%s"):format(u, t),
	}
	if creds then
		table.insert(pt, 2, creds)
		table.insert(pt, 2, "--creds")
	end
	local r, so, se = podman(pt)
	ASSERT(r, "Network or host problem? Unable to pull image.", {
		fn = "pull()",
		command = "podman pull",
		url = u,
		tag = t,
		stdout = so,
		stderr = se,
	})
end
local Config = function(p)
	local M = {}
	M.start = start
	M.stop = stop
	local param = {
		NAME = "Unit name.",
		BASE = "Base unit.",
		URL = "Image URL.",
		TAG = "Image tag.",
		CPUS = "Pin container to CPU(s). Argument to podman --cpuset-cpus.",
		MEM = "Memory limit. Argument to podman --memory.",
		ARGS = "(table) Arguments to any function hooks.",
		IP = "Assigned IP for container",
		SHARES = "CPU share. Argument to podman --cpu-shares.",
		ENVIRONMENT = "(table) or JSON file(string) for environment variables.",
		NETWORK = "private network name.",
		CMD = "Command line to container.",
		IDMAP = "uid gid range.",
		ROOT = "Root directory hierarchy of a container.",
		always_update = "Boolean flag, if `true` always pull the image.",
	}
	M.param = {} --> from user
	M.reg = {} --> generated
	for k in pairs(p) do
		ASSERT(param[k], "Invalid parameter given.", {
			fn = "config()",
			parameter = k,
		})
		M.param[k] = p[k]
	end
	M.param.MEM = M.param.MEM or "512m"
	M.param.ARGS = M.param.ARGS or {}
	M.param.CPUS = M.param.CPUS or "1"
	M.param.IP = M.param.IP or "127.0.0.1"
	M.param.SHARES = M.param.SHARES or "1024"
	M.param.NETWORK = M.param.NETWORK or "host"
	DEBUG("Figuring out container name and network mode...", {})
	if type(M.param.NETWORK) == "table" then
		M.reg.netdata = util.shallowcopy(M.param.NETWORK)
		M.param.NETWORK = "isolated"
	end
	if M.param.NETWORK ~= "host" and M.param.NETWORK ~= "private" and M.param.NETWORK ~= "isolated" then
		M.reg.network = ("container:%s"):format(get_id(M.param.NETWORK .. ".pod"))
		M.reg.cname = ("%s.%s"):format(M.param.NETWORK, M.param.NAME)
	elseif M.param.NETWORK == "private" or M.param.NETWORK == "isolated" then
		local netns = ("/var/run/netns/%s"):format(M.param.NAME)
		ASSERT((fs.isdir(netns) == nil), "Network namespace already exists. Use another name.", {
			fn = "config()",
			name = M.param.NAME,
		})
		M.reg.network = "ns:" .. netns
		M.reg.cname = ("%s.pod"):format(M.param.NAME)
	else
		HOST = true
		M.reg.network = M.param.NETWORK
		M.reg.cname = M.param.NAME
	end
	DEBUG("Processing ENVIRONMENT parameter...", {})
	if M.param.ENVIRONMENT and type(M.param.ENVIRONMENT) == "string" then
		local js = json.decode(fs.read(M.param.ENVIRONMENT))
		ASSERT((type(js) == "table"), "Invalid JSON.", {
			fn = "config()",
			file = M.param.ENVIRONMENT,
			returned = js,
		})
		M.param.ENVIRONMENT = js
	end
	if M.param.ENVIRONMENT and next(M.param.ENVIRONMENT) then
		local password = require("password")
		for k, v in pairs(M.param.ENVIRONMENT) do
			if (k:upper()):contains("PASSWORD") then
				if password.strength(v) < 4 then
					WARN("Weak password!!", {
						password = v
					})
				end
			end
		end
	end
	DEBUG("Generating systemd unit...", {})
	local systemd = {}
	do
		local reqtry, modul
		if M.param.BASE then
			reqtry, modul = pcall(require, "systemd." .. M.param.BASE)
		else
			reqtry, modul = pcall(require, "systemd." .. M.param.NAME)
		end
		if reqtry == true then
			systemd = modul
		end
	end
	do
		local instance
		if next(M.param.ARGS) then
			instance = systemd(M.param.ARGS)
		else
			instance = systemd
		end
		if instance.volumes and next(instance.volumes) then
			volume(instance.volumes)
		end
		if instance.ports and next(instance.ports) then
			local kx, ky = kv_service:put(
				schema.service_ports:format(M.param.NAME),
				json.encode(instance.ports)
			)
			ASSERT(kx, "Host problem? Unable to add ports to etcdb.", {
				fn = "config()",
				error = ky,
			})
		end
		if instance.unit then
			M.reg.unit = instance.unit
		else
			local su = util.shallowcopy(systemd_unit_start)
			if instance.capabilities and next(instance.capabilities) then
				for _, c in ipairs(instance.capabilities) do
					su[#su + 1] = ([[--cap-add %s \]]):format(c)
				end
			end
			if M.param.ENVIRONMENT then
				for k, v in pairs(M.param.ENVIRONMENT) do
					su[#su + 1] = ([[-e "%s=%s" \]]):format(k, v)
				end
			end
			if instance.mounts and next(instance.mounts) then
				for k, v in pairs(instance.mounts) do
					su[#su + 1] = ([[--volume %s:%s \]]):format(k, v)
				end
			end
			if M.param.NETWORK == "isolated" or M.param.NETWORK == "private" then
				su[#su + 1] = [[--dns none \]]
			elseif M.param.NETWORK == "host" then
				su[#su + 1] = [[--dns 127.255.255.53 \]]
			end
			if M.param.IDMAP then
				local idmap = [[--uidmap 0:%s:65536 --gidmap 0:%s:65536 \]]
				su[#su + 1] = idmap:format(M.param.IDMAP, M.param.IDMAP)
			end
			instance.cmd = instance.cmd or ""
			M.param.CMD = M.param.CMD or instance.cmd
			if not M.param.ROOT then
				su[#su + 1] = ("__ID__ %s"):format(M.param.CMD)
			else
				su[#su + 1] = ("--rootfs %s %s"):format(M.param.ROOT, M.param.CMD)
			end
			if M.param.NETWORK == "host" and M.param.IP ~= "127.0.0.1" then
				local n = M.param.NAME
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip link add dev %s type dummy"):format(n)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip link set dev %s mtu 65536"):format(n)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip addr add %s dev %s"):format(M.param.IP, n)
				su[#su + 1] = ("ExecStopPost=/usr/sbin/ip link del dev %s"):format(n)
			elseif M.param.NETWORK == "private" then
				local n = M.param.NAME
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns add %s"):format(n)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip link set lo up"):format(n)
				su[#su + 1] = ("ExecStopPost=/usr/sbin/ip netns del %s"):format(n)
			elseif M.param.NETWORK == "isolated" then
				local nm = M.param.NAME
				local pa = M.reg.netdata.interface
				local de = M.reg.netdata.gateway or ""
				local ip = M.reg.netdata.address
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns add %s"):format(nm)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip link add link %s lan0 type macvlan mode bridge"):format(pa)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip link set lan0 netns %s"):format(nm)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip link set lan0 up"):format(nm)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip link set lo up"):format(nm)
				if ip ~= "dhcp" then
					su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip addr add %s dev lan0"):format(nm, ip)
					su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip route add default via %s dev lan0"):format(nm, de)
				end
				su[#su + 1] = ("ExecStopPost=/usr/sbin/ip netns del %s"):format(nm)
			end
			su[#su + 1] = ""
			su[#su + 1] = "[Install]"
			su[#su + 1] = "WantedBy=multi-user.target"
			su[#su + 1] = ""
			M.reg.unit = table.concat(su, "\n")
		end
	end
	DEBUG("Pulling image if needed...", {})
	if not M.param.ROOT then
		M.reg.id = id(M.param.URL, M.param.TAG)
		if M.param.always_update or not M.reg.id then
			pull(M.param.URL, M.param.TAG)
			M.reg.id = id(M.param.URL, M.param.TAG)
		end
	end
	DEBUG("Assigning IP...", {})
	if M.param.IP and M.param.NETWORK == "host" then
		local r = exec.command("ip", { "link", "show", M.param.NAME })
		ASSERT((r == nil), "BUG? Device already exists.", {
			fn = "config()",
			command = "ip link show",
			name = M.param.NAME,
		})
		local kx, ky = kv_service:put(schema.service_ip:format(M.param.NAME), M.param.IP)
		ASSERT(kx, "Host problem? Unable to add ip to etcdb.", {
			fn = "config()",
			error = ky,
		})
	end
	DEBUG("Generating seccomp profile...", {})
	do
		fs.mkdir("/etc/podman.seccomp")
		local fn = ("/etc/podman.seccomp/%s.json"):format(M.reg.cname)
		local default = require("seccomp")
		local seccomp = json.encode(default)
		ASSERT(fs.write(fn, seccomp), "Host problem? Unable to write seccomp profile.", {
			fn = "config()",
			filename = fn,
		})
	end
	DEBUG("Generating systemd unit...", {})
	podman_interpolate(M)
	ASSERT(fs.isfile("/etc/systemd/system/" .. M.reg.cname .. ".service"), "BUG? Failed to generate unit.", {
		fn = "config()",
		unit = M.reg.cname .. ".service"
	})
	DEBUG("Start or exit depending of type of container...", {})
	if M.param.NETWORK == "host" then
		local systemctl = exec.ctx("systemctl")
		do
			local r, so, se
			r, so, se = systemctl({
				"enable",
				"--no-block",
				"--now",
				("%s.service"):format(M.param.NAME),
			})
			ASSERT(r, "Unable to start service. Check the unit journal.", {
				fn = "config()",
				command = "systemctl enable",
				service = M.param.NAME,
				stdout = so,
				stderr = se,
			})
		end
		local is_active = function()
			local _, so, se = systemctl({ "is-active", M.param.NAME })
			if so == "active\n" then
				return true
			else
				return nil, so, se
			end
		end
		do
			local cmd = util.retry_f(is_active, 10)
			local r, so, se = cmd()
			ASSERT(r, "Failed starting container. Check the unit journal.", {
				fn = "config()",
				name = M.param.NAME,
				stdout = so,
				stderr = se,
			})
		end
		do --> Record into etcdb
			local kx, ky = kv_running:put(M.param.NAME, "ok")
			ASSERT(kx, "Host problem? Unable to add service to etcdb.", {
				fn = "config()",
				error = ky,
			})
		end
		if M.param.NAME ~= "sys_dns" then
			update_hosts()
		end
		kv_running:close()
		kv_service:close()
		OK("Started systemd unit", {
			name = M.param.NAME,
		})
	else
		OK("Container setup done.", {
			name = M.reg.cname,
			network = M.param.NETWORK,
		})
	end
	return M
end
return {
	config = Config,
	get_volume = Get_Volume,
	ports = Ports,
	running = Running,
	reserve_idmap = Reserve_IDMAP,
	release_idmap = Release_IDMAP,
}

