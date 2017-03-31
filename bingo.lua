require "lfs"

lfs.dirfiles = function(name)
    local files = {}
    local function attrdir(path)
        for file in lfs.dir(path) do
            if file ~= "." and file ~= ".." then
                local f = path .. '/' .. file
                local attr = lfs.attributes(f)
                assert (type(attr) == "table")
                if attr.mode == "directory" then
                    attrdir(f)
                else
                    table.insert(files, {f, attr})
                end
            end
        end
    end

    attrdir(name)
    return files
end

lfs.getdirname = function(path)
    local dirs = {}
    for file in lfs.dir(path) do
        if file ~= "." and file ~= ".." then
            local f = path .. '/' .. file
            local attr = lfs.attributes(f)
            assert (type(attr) == "table")
            if attr.mode == "directory" then
                table.insert(dirs, f)
            end
        end
    end

    return dirs
end

table.print = function(node)
    local function tab(amt)
        local str = ""
        for i=1,amt do
            str = str .. "\t"
        end
        return str
    end

    local cache, stack, output = {},{},{}
    local depth = 1
    local output_str = "{\n"

    while true do
        local size = 0
        for k,v in pairs(node) do
            size = size + 1
        end

        local cur_index = 1
        for k,v in pairs(node) do
            if (cache[node] == nil) or (cur_index >= cache[node]) then

                if (string.find(output_str,"}",output_str:len())) then
                    output_str = output_str .. ",\n"
                elseif not (string.find(output_str,"\n",output_str:len())) then
                    output_str = output_str .. "\n"
                end

                table.insert(output,output_str)
                output_str = ""

                local key
                if (type(k) == "number" or type(k) == "boolean") then
                    key = "["..tostring(k).."]"
                else
                    key = "['"..tostring(k).."']"
                end

                if (type(v) == "number" or type(v) == "boolean") then
                    output_str = output_str .. tab(depth) .. key .. " = "..tostring(v)
                elseif (type(v) == "table") then
                    output_str = output_str .. tab(depth) .. key .. " = {\n"
                    table.insert(stack,node)
                    table.insert(stack,v)
                    cache[node] = cur_index+1
                    break
                else
                    output_str = output_str .. tab(depth) .. key .. " = '"..tostring(v).."'"
                end

                if (cur_index == size) then
                    output_str = output_str .. "\n" .. tab(depth-1) .. "}"
                else
                    output_str = output_str .. ","
                end
            else
                if (cur_index == size) then
                    output_str = output_str .. "\n" .. tab(depth-1) .. "}"
                end
            end

            cur_index = cur_index + 1
        end

        if (size == 0) then
            output_str = output_str .. "\n" .. tab(depth-1) .. "}"
        end

        if (#stack > 0) then
            node = stack[#stack]
            stack[#stack] = nil
            depth = cache[node] == nil and depth + 1 or depth - 1
        else
            break
        end
    end

    table.insert(output,output_str)
    output_str = table.concat(output)

    print(output_str)
end

string.trim = function(s) 
    return (string.gsub(s, "^%s*(.-)%s*$", "%1")) 
end

string.split = function(s, p)
    local rt = {}
    string.gsub(s, '[^'.. p ..']+', function(w) table.insert(rt, string.trim(w)) end)
    return rt
end



local HOMEDIR = lfs.currentdir()
local BG = HOMEDIR .. "/target"
local BGLOG = BG .. "/logs"
local BGOUTPUT = BG .. "/output"
local BGBUILD = BG .. "/build"
local BGFS = BG .. "/fs"
local BINWALK = HOMEDIR .. "/src/binwalk-1.0/src/binwalk-script"
local BINWALKMAGIC = HOMEDIR .. "/src/binwalk-1.0/src/binwalk/magic/binwalk"
local BINWALKLOG = BGLOG .. "/binwalk.log"
local BIN = HOMEDIR .. "/333333.bin"

local FS_TYPE = {"squashfs"}


local bingo = {}

function bingo.findfs()
    local fstype = {}
    local pocg = BINWALK .. " -v -m " .. BINWALKMAGIC .. " -f " .. BINWALKLOG .. " " .. BIN
    -- print(pocg)
    -- lfs.chdir(HOMEDIR.."/src/binwalk/src")
    -- print(lfs.currentdir())
    -- local poc = io.popen(pocg)
    -- local out = poc.read("*all")
    -- print(out)

    f = assert(io.popen(pocg))
    for line in f:lines() do
        -- print(line)
        for _, v in ipairs(FS_TYPE) do
            if string.find(string.lower(line), v) then
                fstype[#fstype + 1] = line
            end
        end
    end
    f:close()

    return fstype
end

function bingo.getsections(fstype)
    local list = {}
    -- print(#fstype)
    -- table.print(fstype)
    for _, v in ipairs(fstype) do
        -- print(v)
        local section = string.split(v, ',')
        -- table.print(section)

        local sections = {}

        local node1 = string.split(section[1], '\t')
        sections["offset"] = node1[2]
        sections["fstype"] = node1[3]

        sections["arch"] = section[2]

        local node3 = string.split(section[3], ' ')
        sections["version"] = node3[2]

        local node4 = string.split(section[4], ' ')
        sections["compression"] = node4[2]

        local node5 = string.split(section[5], ' ')
        sections["size"] = node5[2]

        local node6 = string.split(section[6], ' ')
        sections["inodes"] = node6[1]

        local node7 = string.split(section[7], ' ')
        sections["blocksize"] = node7[2]

        -- local node8 = string.split(section[8], ' ')
        -- sections["created"] = node8[2]
        sections["created"] = string.trim(string.sub(section[8], string.find(section[8], ':') + 1, -1))
        
        table.insert(list, sections)
    end

    return list
end

function bingo.extractfstype(sections)
    for _, v in ipairs(sections) do
        local fr = io.open(BIN, 'rb')

        fr:seek("set", tonumber(v["offset"], 16))
        local data = fr:read(tonumber(v["size"]))

        local fwname = BGOUTPUT .. '/' .. string.split(v["fstype"], ' ')[1] .. '_' .. v["offset"] .. '_' .. string.format( "0x%X", tonumber(v["size"]))
        local fw = io.open(fwname, 'wb')
        fw:write(data)
        fw:close()

        fr:close()
    end
end

function bingo.unsquashfs()
    for _, v in ipairs(lfs.dirfiles(BGOUTPUT)) do
        local names = string.split(v[1], '/')
        local name = names[#names]

        if string.find(string.lower(name), "squashfs") then
            local pocg = "unsquashfs -d " .. BGBUILD .. "/" .. name .. " " .. v[1]
            -- print(pocg)
            f = assert(io.popen(pocg))
            for line in f:lines() do
                -- print(line)
            end
            f:close()
        end

    end
end

function bingo.mksquashfs()
    local binnames = string.split(BIN, '/')
    local newbin = BG .. '/new' .. binnames[#binnames]

    for _, v in ipairs(lfs.getdirname(BGBUILD)) do
        local names = string.split(v, '/')
        local name = names[#names]

        if string.find(string.lower(name), "squashfs") then
            local fs = BGFS .. "/" .. name
            os.remove(fs)

            local pocg = "mksquashfs " .. v .. " " .. fs .. " -comp xz -b 1024k -all-root"
            -- print(pocg)
            f = assert(io.popen(pocg))
            for line in f:lines() do
                -- print(line)
            end
            f:close()

            os.execute('cp ' .. BIN .. ' ' .. newbin)

            local bin = string.split(name, '_')
            -- table.print(bin)
            local fw = io.open(newbin, 'rb+')
            fw:seek("set", tonumber(bin[2], 16))
            count = tonumber(bin[3], 16)
            -- print(count)
            for i = count, 1, -1 do
                fw:write(string.char(0xff))
            end

            local fr = io.open(fs, 'rb')
            local data = fr:read("*a")
            fr:close()

            fw:seek("set", tonumber(bin[2], 16))
            fw:write(data)
            fw:close()
        end

    end

    print("Output:", newbin)
end

-- table.print(_G)
if arg[1] == '-b' then
    bingo.mksquashfs()
else
    BIN = arg[1]
    os.execute("rm -rf " .. BG)
    lfs.mkdir(BG)
    lfs.mkdir(BGLOG)
    lfs.mkdir(BGOUTPUT)
    lfs.mkdir(BGBUILD)
    lfs.mkdir(BGFS)

    local fstype = bingo.findfs()
    local sections = bingo.getsections(fstype)

    -- print(#sections)
    -- table.print(sections)
    bingo.extractfstype(sections)

    bingo.unsquashfs()
end
