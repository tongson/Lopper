local DSL = "podman"
local DEBUG = false
local HOST = false
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
ExecStart=/usr/bin/podman run --name __CNAME__ \
--security-opt seccomp=/etc/podman.seccomp/__NAME__.json \
--security-opt apparmor=unconfined \
--security-opt label=disable \
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
local Ok = function(msg, tbl)
	tbl._module = DSL
	return lopper.Ok(msg, tbl)
end
local Warn = function(msg, tbl)
	tbl._module = DSL
	return lopper.Warn(msg, tbl)
end
local Debug = function(msg, tbl)
	if DEBUG then
		tbl._module = DSL
		return lopper.Debug(msg, tbl)
	end
end
local Assert = function(ret, msg, tbl)
	if ret == nil then
		tbl._module = DSL
		kv_running:close()
		kv_service:close()
		return lopper.Panic(msg, tbl)
	end
end
local E = {}
local podman = exec.ctx("podman")
local get_id = function(n)
	local try = util.retry_f(podman)
	local r, so, se = try({
			"inspect",
			"--format",
			"json",
			n,
		})
	Assert(r, "Unable to find container.", {
		stdout = so,
		stderr = se,
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
	Assert(ret, "Failure listing volumes", {
		what = "podman",
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
			Assert(ret, "unable to create volume", {
				what = "podman",
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
				Assert(ret, "error executing volume command", {
					what = "sh",
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
	Assert(
		fs.write(dns_config .. "/hosts", hosts_file),
		"unable to write system HOSTS file",
		{}
	)
end
E.reserve_idmap = function(id)
	id = id or lopper.ID
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
	Assert((n > max), "Reached maximum possible allocation.", {})
	Ok("Reserved idmap allocation.", {
		range = key .. "-" .. tostring(n+65536),
		mark = id,
	})
	return key
end
E.release_idmap = function(key)
	local n = tonumber(key)
	local kv_idmap = bitcask.open("/etc/podman.etcdb/idmap")
	local r = kv_idmap:delete(key)
	kv_idmap:close()
	Ok("Released idmap allocation.", {
		range = key .. "-" .. tostring(n+65536),
	})
	return r
end
E.running = function(direct)
	if not direct then
		return kv_running:keys()
	end
	-- Not from the etcdb but directly from podman
	local r, so, se = podman({ "ps", "-a", "--format", "json" })
	Assert(r, "failure running podman command", {
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
E.ports = function(srv)
	-- From etcdb
	local ports = kv_service:get(schema.service_ports:format(srv))
	return json.decode(ports)
end
E.volume = get_volume
local stop = function(T)
	-- Does removal from kv_running etcdb and updates dns hosts.
	local c = T.reg.CNAME
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
	Assert(cmd(), "failed stopping container", {
		name = c,
		stdout = so,
		stderr = se,
	})
	if HOST then
		if kv_running:has(c) then
			local try = util.retry_f(kv_running.delete)
			local deleted = try(kv_running, c)
			kv_running:close()
			Assert(deleted, "unable to remove container from etcdb/running", {
				name = c,
			})
		end
		update_hosts()
	end
	Ok("Stopped container(service).", {
		name = c,
	})
end
local start = function(T, stats)
	local c = T.reg.CNAME
	fs.mkdir("/var/log/podman") -- Checked in the next mkdir()
	local logdir = "/var/log/podman/" .. lopper.ID
	if not fs.isdir(logdir) then
		Assert(fs.mkdir(logdir), "unable to create logging directory", {
			directory = logdir,
		})
	end
	local journalctl = exec.ctx("journalctl")
	local cursor
	do
		local r, so, se = journalctl({"-u", c, "-o", "json", "-n", "1"})
		Assert(r, "unable to get cursor from journalctl", {
			name = c,
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
		Assert(cmd(), "failed starting container", {
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
				Assert(nil, "Did not return a valid output.", {
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
	Ok("Started container(service).", data)
end
E.enable = function(c)
	local systemctl = exec.ctx("systemctl")
	local so, se
	systemctl({"daemon-reload"})
	systemctl({ "enable", "--no-block", "--now", c })
	local is_active = function()
		_, so, se = systemctl({ "is-active", c })
		if so == "active\n" then
			return true
		else
			return nil, so, se
		end
	end
	local cmd = util.retry_f(is_active, 10)
	Assert(cmd(), "failed starting container", {
		name = c,
		stdout = so,
		stderr = se,
	})
	if HOST then
		if not kv_running:has(c) then
			local try = util.retry_f(kv_running.put)
			local added = try(kv_running, c)
			kv_running:close()
			Assert(added, "unable to add container to etcdb/running", {
				name = c,
			})
		end
		update_hosts()
	end
	Ok("Started container(service).", {
		name = c,
	})
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
		fname = ("/etc/systemd/system/%s.service"):format(A.reg.CNAME)
	end
	local unit, changed = A.reg.unit:gsub("__ID__", A.reg.id)
	unit, changed = unit:gsub("__NAME__", A.param.NAME)
	Assert((changed > 1), "unable to interpolate name", {
		what = "string.gsub",
		changed = false,
		to = A.param.NAME,
	})
	unit, changed = unit:gsub("__CNAME__", A.reg.CNAME)
	Assert((changed == 2), "unable to interpolate container name", {
		what = "string.gsub",
		changed = false,
		to = A.reg.NAME,
	})
	-- Should only match once.
	Assert((changed == 1), "unable to interpolate image ID", {
		what = "string.gsub",
		changed = false,
		to = A.reg.id,
	})
	if unit:contains("__IP__") then
		unit, changed = unit:gsub("__IP__", A.param.IP)
		Assert((changed >= 1), "unable to interpolate IP", {
			what = "string.gsub",
			changed = false,
			to = A.param.IP,
		})
	end
	unit, changed = unit:gsub("__CPUS__", A.param.CPUS)
	-- Should only match once.
	Assert((changed == 1), "unable to interpolate cpuset-cpus", {
		what = "string.gsub",
		changed = false,
		to = A.param.CPUS,
	})
	unit, changed = unit:gsub("__MEM__", A.param.MEM)
	-- Should only match once.
	Assert((changed == 1), "unable to interpolate memory", {
		what = "string.gsub",
		changed = false,
		to = A.param.MEM,
	})
	unit, changed = unit:gsub("__SHARES__", A.param.SHARES)
	-- Should only match once.
	Assert((changed == 1), "unable to interpolate cpu-shares", {
		what = "string.gsub",
		changed = false,
		to = A.param.SHARES,
	})
	unit, changed = unit:gsub("__NETWORK__", A.reg.NETWORK)
	-- Should only match once.
	Assert((changed == 1), "unable to interpolate network", {
		what = "string.gsub",
		changed = false,
		to = A.reg.NETWORK,
	})
	Assert(fs.write(fname, unit), "unable to write unit", {
		what = "fs.write",
		file = fname,
	})
	if A.param.NETWORK == "host" then
		local r, so, se = systemctl({
			"enable",
			"--no-block",
			"--now",
			("%s.service"):format(A.param.NAME),
		})
		Assert(r, "unable to start service", {
			what = "systemctl",
			command = "enable",
			service = A.param.NAME,
			stdout = so,
			stderr = se,
		})
	end
end
local id = function(u, t)
	local r, so, se = podman({
		"images",
		"--format",
		"json",
	})
	Assert(r, "unable to list images", {
		what = "podman",
		command = "images",
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
	Assert(r, "unable to pull image", {
		what = "podman",
		command = "pull",
		url = u,
		tag = t,
		stdout = so,
		stderr = se,
	})
end
E.config = function(p)
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
		always_update = "Boolean flag, if `true` always pull the image.",
	}
	M.param = {} --> from user
	M.reg = {} --> generated
	for k in pairs(p) do
		Assert(param[k], "Invalid parameter given.", {
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
	Debug("Figuring out container name...", {})
	if type(M.param.NETWORK) == "table" then
		M.reg.NETDATA = util.shallowcopy(M.param.NETWORK)
		M.param.NETWORK = "isolated"
	end
	if M.param.NETWORK ~= "host" and M.param.NETWORK ~= "private" and M.param.NETWORK ~= "isolated" then
		M.reg.NETWORK = ("container:%s"):format(get_id(M.param.NETWORK .. ".pod"))
		M.reg.CNAME = ("%s.%s"):format(M.param.NETWORK, M.param.NAME)
	elseif M.param.NETWORK == "private" or M.param.NETWORK == "isolated" then
		local netns = ("/var/run/netns/%s"):format(M.param.NAME)
		Assert((fs.isdir(netns) == nil), "Network namespace already exists.", {
			name = M.param.NAME,
		})
		M.reg.NETWORK = "ns:" .. netns
		M.reg.CNAME = ("%s.pod"):format(M.param.NAME)
	else
		HOST = true
		M.reg.NETWORK = M.param.NETWORK
		M.reg.CNAME = M.param.NAME
	end
	Debug("Processing ENVIRONMENT parameter...", {})
	if M.param.ENVIRONMENT and type(M.param.ENVIRONMENT) == "string" then
		local js = json.decode(fs.read(M.param.ENVIRONMENT))
		Assert(js, "Invalid JSON.", {
			file = M.param.ENVIRONMENT
		})
		M.param.ENVIRONMENT = js
	end
	if M.param.ENVIRONMENT and next(M.param.ENVIRONMENT) then
		local password = require("password")
		for k, v in pairs(M.param.ENVIRONMENT) do
			if (k:upper()):contains("PASSWORD") then
				if password.strength(v) < 4 then
					Warn("Weak password!!", {
						password = v
					})
				end
			end
		end
	end
	Debug("Generating systemd unit...", {})
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
			Assert(kx, "unable to add ports to etcdb", {
				error = ky,
			})
		end
		M.reg.address_families = instance.address_families or "AF_INET"
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
			if M.param.NETWORK == "host" then
				su[#su + 1] = [[--dns 127.255.255.53 \]]
			end
			if M.param.IDMAP then
				local idmap = [[--uidmap 0:%s:65536 --gidmap 0:%s:65536 \]]
				su[#su + 1] = idmap:format(M.param.IDMAP, M.param.IDMAP)
			end
			instance.cmd = instance.cmd or ""
			M.param.CMD = M.param.CMD or instance.cmd
			su[#su + 1] = ("__ID__ %s"):format(M.param.CMD)
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
				local pa = M.reg.NETDATA.interface
				local de = M.reg.NETDATA.gateway
				local ip = M.reg.NETDATA.address
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns add %s"):format(nm)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip link add link %s lan0 type ipvlan mode l2"):format(pa)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip link set lan0 netns %s"):format(nm)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip link set lan0 up"):format(nm)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip link set lo up"):format(nm)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip addr add %s dev lan0"):format(nm, ip)
				su[#su + 1] = ("ExecStartPre=/usr/sbin/ip netns exec %s ip route add default via %s dev lan0"):format(nm, de)
				su[#su + 1] = ("ExecStopPost=/usr/sbin/ip netns del %s"):format(nm)
			end
			su[#su + 1] = ""
			su[#su + 1] = "[Install]"
			su[#su + 1] = "WantedBy=multi-user.target"
			su[#su + 1] = ""
			M.reg.unit = table.concat(su, "\n")
		end
	end
	Debug("Pulling image if needed...", {})
	M.reg.id = id(M.param.URL, M.param.TAG)
	if M.param.always_update or not M.reg.id then
		pull(M.param.URL, M.param.TAG)
		M.reg.id = id(M.param.URL, M.param.TAG)
	end
	Debug("Assigning IP...", {})
	if M.param.IP and M.param.NETWORK == "host" then
		local r = exec.command("ip", { "link", "show", M.param.NAME })
		Assert((r == nil), "device already exists.", {
			command = "ip link show",
			name = M.param.NAME,
		})
		local kx, ky = kv_service:put(schema.service_ip:format(M.param.NAME), M.param.IP)
		Assert(kx, "unable to add ip to etcdb", {
			error = ky,
		})
	end
	Debug("Generating seccomp profile...", {})
	do
		fs.mkdir("/etc/podman.seccomp")
		local fn = ("/etc/podman.seccomp/%s.json"):format(M.param.NAME)
		local default = require("seccomp")
		local seccomp = json.encode(default)
		Assert(fs.write(fn, seccomp), "unable to write seccomp profile", {
			filename = fn,
		})
	end
	Debug("Generating systemd unit...", {})
	podman_interpolate(M)
	Assert(fs.isfile("/etc/systemd/system/" .. M.reg.CNAME .. ".service"), "Failed to generate unit.", {
		unit = M.reg.CNAME .. ".service"
	})
	Debug("Start or exit depending of type of container...", {})
	if M.param.NETWORK == "host" then
		local systemctl = exec.ctx("systemctl")
		local so, se
		local is_active = function()
			_, so, se = systemctl({ "is-active", M.param.NAME })
			if so == "active\n" then
				return true
			else
				return nil, so, se
			end
		end
		local cmd = util.retry_f(is_active, 10)
		Assert(cmd(), "failed starting container", {
			name = M.param.NAME,
			stdout = so,
			stderr = se,
		})
		do --> Record into etcdb
			local kx, ky = kv_running:put(M.param.NAME, "ok")
			Assert(kx, "unable to add service to etcdb", {
				error = ky,
			})
		end
		if M.param.NAME ~= "sys_dns" then
			update_hosts()
		end
		kv_running:close()
		kv_service:close()
		Ok("Started systemd unit", {
			name = M.param.NAME,
		})
	else
		Ok("Container setup done.", {
			name = M.param.NAME,
			network = M.param.NETWORK,
		})
	end
	return M
end
return E
