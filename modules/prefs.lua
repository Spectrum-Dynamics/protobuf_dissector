----------------------------------------
--
-- Copyright (c) 2015, 128 Technology, Inc.
--
-- author: Hadriel Kaplan <hadriel@128technology.com>
--
-- This code is licensed under the MIT license.
--
-- Version: 1.0
--
------------------------------------------

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert
local derror   = Settings.derror


local Prefs = {}


local range_rgx = GRegex.new("([0-9]+)\\s*(?:-\\s*([0-9]+))?")
local function getRange(range)
    local t = {}
    for first, second in GRegex.gmatch(range, range_rgx) do
        if first then
            first = tonumber(first)
            if second then
                second = tonumber(second)
                for port=first, second do
                    t[port] = true
                end
            else
                t[first] = true
            end
        end
    end
    return t
end


function Prefs:create(proto)
    dassert(proto, "Programming error: Prefs:create() called without created Proto")

    -- local tcp_ports = self.tcp_ports
    local tcp_ports = "0"
    proto.prefs.tcp_ports = Pref.range("TCP port range for protocol", tcp_ports, "The range of tcp port numbers to decode the protocol for", 65535)

    -- this creates a new function, so the local tcp_ports variable is saved as an
    -- upvalue and does not need to be stored in the self/proto object
    proto.prefs_changed = function()
        if tcp_ports ~= proto.prefs.tcp_ports then
            -- remove old ports, if not 0
            if tcp_ports ~= "0" then
                for port in pairs(getRange(tcp_ports)) do
                    DissectorTable.get("tcp.port"):remove(port, proto)
                end
            end

            -- save new range
            tcp_ports = proto.prefs.tcp_ports

            -- add new ports, if not 0
            if tcp_ports ~= "0" then
                for port in pairs(getRange(tcp_ports)) do
                    DissectorTable.get("tcp.port"):add(port, proto)
                end
            end
        end
    end
end


return Prefs
