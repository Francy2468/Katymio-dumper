-- Lua Sandbox Configuration
-- This file provides safe defaults for executing untrusted Lua scripts

-- Restrict dangerous functions
local safe_io = {
    type = function(...) return io.type(...) end,
    -- All file operations are disabled
}

local safe_os = {
    clock = os.clock,
    date = os.date,
    difftime = os.difftime,
    time = os.time,
    -- All system operations disabled (execute, exit, getenv, remove, rename, tmpname)
}

local safe_debug = {
    traceback = debug.traceback,
    getinfo = function(func, what)
        -- Only allow source location info
        if type(func) == "function" then
            local info = debug.getinfo(func, what or "Sl")
            if info then
                return {
                    source = info.source or "?",
                    linedefined = info.linedefined or 0,
                    currentline = info.currentline or 0,
                }
            end
        end
        return nil
    end,
    -- All other debug functions disabled
}

-- Create safe environment
local function create_sandbox_env()
    return {
        -- Safe base functions
        assert = assert,
        error = error,
        ipairs = ipairs,
        next = next,
        pairs = pairs,
        pcall = pcall,
        select = select,
        tonumber = tonumber,
        tostring = tostring,
        type = type,
        unpack = unpack or table.unpack,
        xpcall = xpcall,
        
        -- Safe standard libraries
        coroutine = coroutine,
        string = string,
        table = table,
        math = math,
        
        -- Restricted libraries
        io = safe_io,
        os = safe_os,
        debug = safe_debug,
        
        -- Disabled
        load = nil,
        loadfile = nil,
        loadstring = nil,
        dofile = nil,
        require = nil,
        module = nil,
        package = nil,
        
        -- Add _VERSION
        _VERSION = _VERSION,
    }
end

return {
    create_sandbox = create_sandbox_env,
    safe_io = safe_io,
    safe_os = safe_os,
    safe_debug = safe_debug,
}
