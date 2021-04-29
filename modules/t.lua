local podman=exec.ctx"podman"
local util=require"util"
local r, so, se = podman({                     
                "images",                                          
                "--format",                  
                "json",                 
        })                        
	local json = require"json"
        local j = json.decode(so)
	local u = "mariadb"
	local t = "10.5"
        _, u = util.path_split(u)
        local name = ("%s:%s"):format(u, t)
        for i = 1, #j do
		if table.find(j[i].Names, name) then
			print (j[i].Id)
                end
        end

