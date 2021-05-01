local DSL = "podman"
local systemd_unit = {
	[===[
[Unit]
Description=__NAME__ Container
Wants=network.target
After=network-online.target

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
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
RestrictAddressFamilies=__ADDRESS_FAMILIES__
ExecStart=/usr/bin/podman run --name __NAME__ \
--security-opt seccomp=/etc/podman.seccomp/__NAME__.json \
--security-opt apparmor=unconfined \
--rm \
--replace \
--dns 127.255.255.53 \
--network host \
--hostname __NAME__ \
--sdnotify conmon \
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
local dummy_netdev = [[
[NetDev]
Name=__NAME__
Kind=dummy
]]
local dummy_network = [[
[Match]
Name=__NAME__
[Network]
Address=__IP__/32
LinkLocalAddressing=no
IPv6AcceptRA=no
[Link]
MTUBytes=65536
]]
fs.mkdir("/etc/podman.etcdb")
local bitcask = require("bitcask")
local kv_running = bitcask.open("/etc/podman.etcdb/running")
local kv_service = bitcask.open("/etc/podman.etcdb/service")
local lopper = require("lopper")
local json = require("json")
local util = require("util")
local ok = function(msg, tbl)
	tbl._module = DSL
	return lopper.Ok(msg, tbl)
end
local panic = function(ret, msg, tbl)
	if not ret then
		tbl._module = DSL
		kv_running:close()
		kv_service:close()
		return lopper.Panic(msg, tbl)
	end
end
local M = {}
local podman = exec.ctx("podman")
local get_volume = function(n)
	local ret, so, se = podman({
		"volume",
		"inspect",
		"--all",
	})
	panic(ret, "Failure listing volumes", {
		what = "podman",
		command = "volume-ls",
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
			panic(ret, "unable to create volume", {
				what = "podman",
				command = "volume-create",
				stdout = so,
				stderr = se,
			})
		end
		local mountpoint = get_volume(x)
		local sh = exec.ctx("sh")
		if type(y) == "table" then
			for _, cmd in ipairs(y) do
				local ret, so, se = sh({ "-c", cmd:gsub("__MOUNTPOINT__", mountpoint) })
				panic(ret, "error executing volume command", {
					what = "sh",
					command = "volume-command",
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
			hosts[#hosts + 1] = ("%s %s"):format(ip, srv)
		end
	end
	hosts[#hosts + 1] = ""
	local hosts_file = table.concat(hosts, "\n")
	panic(
		fs.write(dns_config .. "/hosts", hosts_file),
		"unable to write system HOSTS file",
		{}
	)
end
M.get_running = function(direct)
	if not direct then
		return kv_running:keys()
	end
	-- Not from the etcdb but directly from podman
	local r, so, se = podman({ "ps", "-a", "--format", "json" })
	panic(r, "failure running podman command", {
		command = "ps",
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
M.get_ports = function(srv)
	-- From etcdb
	local ports = kv_service:get(schema.service_ports:format(srv))
	return json.decode(ports)
end
M.stop = function(c)
	local systemctl = exec.ctx("systemctl")
	local so, se
	systemctl({ "disable", "--no-block", "--now", c })
	local is_inactive = function()
		_, so, se = systemctl({ "status", c })
		if so:contains("inactive") then
			return true
		else
			return nil, so, se
		end
	end
	local cmd = util.retry_f(is_inactive, 10)
	panic(cmd(), "failed stopping container", {
		name = c,
		stdout = so,
		stderr = se,
	})
	if kv_running:has(c) then
		local try = util.retry_f(kv_running.delete)
		local deleted = try(kv_running, c)
		kv_running:close()
		panic(deleted, "unable to remove container from etcdb/running", {
			name = c,
		})
	end
	update_hosts()
	ok("Stopped container(service).", {
		name = c,
	})
end
local start = function(A)
	local systemctl = exec.ctx("systemctl")
	systemctl({
		"disable",
		"--no-block",
		"--now",
		("%s.service"):format(A.param.NAME),
	})
	local fname = ("/etc/systemd/system/%s.service"):format(A.param.NAME)
	local unit, changed = A.reg.unit:gsub("__ID__", A.reg.id)
	unit, changed = unit:gsub("__NAME__", A.param.NAME)
	panic((changed > 1), "unable to interpolate name", {
		what = "string.gsub",
		changed = false,
		to = A.param.NAME,
	})
	unit, changed = unit:gsub("__ADDRESS_FAMILIES__", A.param.ADDRESS_FAMILIES)
	-- Should only match once.
	panic((changed == 1), "unable to interpolate RestrictAddressFamilies", {
		what = "string.gsub",
		changed = false,
		to = A.param.ADDRESS_FAMILIES,
	})
	-- Should only match once.
	panic((changed == 1), "unable to interpolate image ID", {
		what = "string.gsub",
		changed = false,
		to = A.reg.id,
	})
	if unit:contains("__IP__") then
		unit, changed = unit:gsub("__IP__", A.param.IP)
		panic((changed >= 1), "unable to interpolate IP", {
			what = "string.gsub",
			changed = false,
			to = A.param.IP,
		})
	end
	unit, changed = unit:gsub("__CPUS__", A.param.CPUS)
	-- Should only match once.
	panic((changed == 1), "unable to interpolate cpuset-cpus", {
		what = "string.gsub",
		changed = false,
		to = A.param.CPUS,
	})
	unit, changed = unit:gsub("__MEM__", A.param.MEM)
	-- Should only match once.
	panic((changed == 1), "unable to interpolate memory", {
		what = "string.gsub",
		changed = false,
		to = A.param.MEM,
	})
	unit, changed = unit:gsub("__SHARES__", A.param.SHARES)
	-- Should only match once.
	panic((changed == 1), "unable to interpolate cpu-shares", {
		what = "string.gsub",
		changed = false,
		to = A.param.SHARES,
	})
	panic(fs.write(fname, unit), "unable to write unit", {
		what = "fs.write",
		file = fname,
	})
	local r, so, se = systemctl({
		"enable",
		"--no-block",
		"--now",
		("%s.service"):format(A.param.NAME),
	})
	panic(r, "unable to start service", {
		what = "systemctl",
		command = "enable",
		service = A.param.NAME,
		stdout = so,
		stderr = se,
	})
end
local id = function(u, t)
	local r, so, se = podman({
		"images",
		"--format",
		"json",
	})
	panic(r, "unable to list images", {
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
	local r, so, se = podman({
		"pull",
		"--tls-verify",
		("%s:%s"):format(u, t),
	})
	panic(r, "unable to pull image", {
		what = "podman",
		command = "pull",
		url = u,
		tag = t,
		stdout = so,
		stderr = se,
	})
end
local assign_ip = function(n, ip)
	local netdev = dummy_netdev:gsub("__NAME__", n)
	local network = dummy_network:gsub("__NAME__", n)
	network = network:gsub("__IP__", ip)
	local fnetdev = ("/etc/systemd/network/%s.netdev"):format(n)
	local fnetwork = ("/etc/systemd/network/%s.network"):format(n)
	panic(fs.write(fnetdev, netdev), "unable to write .netdev configuration", {
		what = "dummy network",
		file = fnetdev,
	})
	panic(
		fs.write(fnetwork, network),
		"unable to write .network configuration",
		{
			what = "dummy network",
			file = fnetwork,
		}
	)
	local systemctl = exec.ctx("systemctl")
	systemctl({ "restart", "systemd-networkd" })
	local netcheck = function(wh)
		local ipargs = { "-j", "addr", "show", "dev", n }
		local ipcmd = util.retry_f(exec.ctx("ip"))
		local ret, so, se = ipcmd(ipargs)
		panic(ret, "failure running ip command", {
			what = "dummy network",
			stdout = so,
			stderr = se,
		})
		return table.find(json.decode(so), wh)
	end
	local ifcheck = util.retry_f(netcheck)
	panic(ifcheck(n), "ifname did not match", {
		what = "dummy network",
		expected = n,
	})
	local ipcheck = util.retry_f(netcheck)
	panic(ipcheck(ip), "local IP did not match", {
		what = "dummy network",
		expected = ip,
	})
	return ip
end
setmetatable(M, {
	__call = function(_, p)
		local param = {
			NAME = "Unit name.",
			URL = "Image URL.",
			TAG = "Image tag.",
			CPUS = "Pin container to CPU(s). Argument to podman --cpuset-cpus.",
			MEM = "Memory limit. Argument to podman --memory.",
			ARGS = "(table) Arguments to any function hooks.",
			IP = "Assigned IP for container",
			SHARES = "CPU share. Argument to podman --cpu-shares.",
			ADDRESS_FAMILIES = "Address families allowed. Value of systemd RestrictAddressFamilies. Default: AF_INET.",
			CAPABILITIES = "(table) Linux capabilities, example: net_bind_service.",
			ENVIRONMENT = "(table) Environment variables.",
			CMD = "Command line to container.",
			always_update = "Boolean flag, if `true` always pull the image.",
		}
		M.param = {} --> from user
		M.reg = {} --> generated
		for k in pairs(p) do
			if not param[k] then
				panic(nil, "Invalid parameter given.", {
					parameter = k,
				})
			else
				M.param[k] = p[k]
			end
		end
		M.param.MEM = M.param.MEM or "512m"
		M.param.ARGS = M.param.ARGS or {}
		M.param.CPUS = M.param.CPUS or "1"
		M.param.IP = M.param.IP or "127.0.0.1"
		M.param.SHARES = M.param.SHARES or "1024"
		M.param.ADDRESS_FAMILIES = M.param.ADDRESS_FAMILIES or "AF_INET"

		local systemd = require("systemd." .. M.param.NAME)
		do
			local instance
			if next(M.param.ARGS) then
				instance = systemd(M.param.ARGS)
			else
				instance = systemd
			end
			if next(instance.volumes) then
				volume(instance.volumes)
				for vn in pairs(instance.volumes) do
					ok("Checked volume", {
						name = vn,
					})
				end
			end
			if instance.ports and next(instance.ports) then
				local kx, ky = kv_service:put(
					schema.service_ports:format(M.param.NAME),
					json.encode(instance.ports)
				)
				panic(kx, "unable to add ports to etcdb", {
					error = ky,
				})
			end
			if instance.unit then
				M.reg.unit = instance.unit
			else
				if M.param.CAPABILITIES then
					for _, c in ipairs(M.param.CAPABILITIES) do
						systemd_unit[#systemd_unit + 1] = ([[--cap-add %s \]]):format(c)
					end
				end
				if M.param.ENVIRONMENT then
					for _, e in ipairs(M.param.ENVIRONMENT) do
						systemd_unit[#systemd_unit + 1] = ([[-e "%s" \]]):format(e)
					end
				end
				for k, v in pairs(instance.mounts) do
					systemd_unit[#systemd_unit + 1] = ([[--volume %s:%s \]]):format(k, v)
				end
				M.param.CMD = M.param.CMD or instance.cmd
				systemd_unit[#systemd_unit + 1] = ("__ID__ %s"):format(M.param.CMD)
				systemd_unit[#systemd_unit + 1] = ""
				systemd_unit[#systemd_unit + 1] = "[Install]"
				systemd_unit[#systemd_unit + 1] = "WantedBy=multi-user.target"
				systemd_unit[#systemd_unit + 1] = ""
				M.reg.unit = table.concat(systemd_unit, "\n")
			end
		end

		-- pull
		M.reg.id = id(M.param.URL, M.param.TAG)
		if M.param.always_update or not M.reg.id then
			pull(M.param.URL, M.param.TAG)
			ok("Pulled image", {
				url = M.param.URL,
				tag = M.param.TAG,
			})
			M.reg.id = id(M.param.URL, M.param.TAG)
			ok("Got image ID", {
				id = M.reg.id,
			})
		end
		if M.param.IP then
			assign_ip(M.param.NAME, M.param.IP)
			local kx, ky = kv_service:put(schema.service_ip:format(M.param.NAME), M.param.IP)
			panic(kx, "unable to add ip to etcdb", {
				error = ky,
			})
		end
		-- start
		do
			fs.mkdir("/etc/podman.seccomp")
			local fn = ("/etc/podman.seccomp/%s.json"):format(M.param.NAME)
			local default = require("seccomp")
			local seccomp = json.encode(default)
			panic(fs.write(fn, seccomp), "unable to write seccomp profile", {
				filename = fn,
			})
		end
		start(M)
		do
			local kx, ky = kv_running:put(M.param.NAME, "ok")
			panic(kx, "unable to add service to etcdb", {
				error = ky,
			})
		end
		if M.param.NAME ~= "sys_dns" then
			update_hosts()
		end
		kv_running:close()
		kv_service:close()
		ok("Started systemd unit", {
			name = M.param.NAME,
		})
	end,
})
return M
