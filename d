-- FlowAuth v4 loader — cleaned (decoded strings, comments, same behavior)
-- Flow: fetch blob -> size check -> Adler-32 check -> loadstring("=FlowAuthRuntime")
--       -> stash _bsdata0 handoff -> runtime(credential)

return (function(...)
    local kind, protect, raise = type, pcall, error
    local getEnvironment, setEnvironment, compile = getfenv, setfenv, loadstring

    if kind(getEnvironment) ~= "function" or kind(setEnvironment) ~= "function" then
        return nil, "Silent execution is unavailable in this executor"
    end

    -- ---------------------------------------------------------------
    -- Base / shared environments
    -- ---------------------------------------------------------------
    local base = getEnvironment()
    local inherited = rawget(base, "__flowauth_console_scope")
    local shared = base

    if kind(getgenv) == "function" then
        local ok, value = protect(getgenv)
        if ok and kind(value) == "table" then shared = value end
    end

    if kind(inherited) == "table"
        and kind(inherited.base) == "table"
        and kind(inherited.compile) == "function" then
        base, shared, compile = inherited.base, inherited.shared, inherited.compile
    end

    local unpackValues = table.unpack or unpack
    local function pack(...) return { n = select("#", ...), ... } end

    -- ---------------------------------------------------------------
    -- Console quiet gate
    --   quiet == nil  -> buffer output
    --   quiet == true -> suppress
    --   quiet == false -> flush and pass through
    -- ---------------------------------------------------------------
    local quiet = nil
    local pending = {}
    local authoredError
    local nativeProtectedRuntime = false

    local nativePrint, nativeWarn = base.print, base.warn
    local nativeRawGet, nativeRawSet = rawget, rawset

    local function output(fn, ...)
        if quiet == nil then
            if #pending < 32 then
                pending[#pending + 1] = { fn, pack(...) }
            end
        elseif not quiet and kind(fn) == "function" then
            fn(...)
        end
    end

    local function decide(value)
        if quiet ~= nil then return end
        quiet = value
        if not quiet then
            for _, entry in ipairs(pending) do
                if kind(entry[1]) == "function" then
                    entry[1](unpackValues(entry[2], 1, entry[2].n))
                end
            end
        end
        pending = {}
    end

    local scope, sharedScope = {}, {}
    setmetatable(scope,       { __index = base,   __newindex = base })
    setmetatable(sharedScope, { __index = shared, __newindex = shared })

    local function mutedPrint(...) output(nativePrint, ...) end
    local function mutedWarn(...)  output(nativeWarn,  ...) end

    -- ---------------------------------------------------------------
    -- loadstring interception
    -- ---------------------------------------------------------------
    local function scopedCompile(text, name)
        -- Luraph STATIC_ENVIRONMENT: the runtime chunk keeps native globals.
        -- Env rebinding would break it, so pass straight through.
        if name == "=FlowAuthRuntime" then
            nativeProtectedRuntime = true
            return compile(text, name)
        end

        if kind(text) == "string" then
            local prefix = string.sub(text, 1, 256)
            if string.find(prefix, "-- FlowAuth console: silent", 1, true) then
                decide(true)
            elseif string.find(prefix, "-- FlowAuth console: normal", 1, true) then
                decide(false)
            end
        end

        local chunk, reason = compile(text, name)
        if kind(chunk) == "function" then
            if name == "=FlowAuth" or name == "=FlowAuthInit" or name == "=FlowAuthUI" then
                setEnvironment(chunk, base)
                local function authored(fn)
                    return function(...)
                        local values = pack(protect(fn, ...))
                        if not values[1] then
                            authoredError = values[2]
                            raise(values[2], 0)
                        end
                        if name == "=FlowAuthInit" and kind(values[2]) == "function" then
                            values[2] = authored(values[2])
                        end
                        return unpackValues(values, 2, values.n)
                    end
                end
                return authored(chunk)
            end
            setEnvironment(chunk, scope)
        end
        return chunk, reason
    end

    -- ---------------------------------------------------------------
    -- Scoped rawget/rawset: writes to base/shared, reads fall back
    -- ---------------------------------------------------------------
    local function scopedRawGet(environment, key)
        if environment == scope or environment == sharedScope then
            local own = nativeRawGet(environment, key)
            if own ~= nil then return own end
            return nativeRawGet(environment == scope and base or shared, key)
        end
        return nativeRawGet(environment, key)
    end

    local function scopedRawSet(environment, key, value)
        if environment == scope then
            nativeRawSet(base, key, value); return environment
        end
        if environment == sharedScope then
            nativeRawSet(shared, key, value); return environment
        end
        return nativeRawSet(environment, key, value)
    end

    for _, environment in ipairs({ scope, sharedScope }) do
        rawset(environment, "__flowauth_console_scope", { base = base, shared = shared, compile = compile })
        rawset(environment, "rawget",     scopedRawGet)
        rawset(environment, "rawset",     scopedRawSet)
        rawset(environment, "print",      mutedPrint)
        rawset(environment, "warn",       mutedWarn)
        rawset(environment, "loadstring", scopedCompile)
        rawset(environment, "getgenv",    function() return sharedScope end)
        rawset(environment, "_G",         sharedScope)
    end

    -- ===============================================================
    -- MAIN CHAIN
    -- ===============================================================
    local function run(...)
        local credential = ...
        local type, pcall, error, tostring, tonumber = type, pcall, error, tostring, tonumber
        local rawset, getfenv = rawset, getfenv
        local globals, host = _G, game
        local byte, gsub, find = string.byte, string.gsub, string.find
        local wait  = type(task) == "table" and task.wait
        local clock = os.clock
        local compile = loadstring

        local function member(value, key)
            local ok, result = pcall(function() return value[key] end)
            if ok then return result end
        end

        -- Credential resolution
        local keyless = false
        if keyless then
            credential = ""
        elseif type(credential) ~= "string" then
            for lv = 2, 4 do
                local f, sc = pcall(getfenv, lv)
                local v = f and type(sc) == "table" and member(sc, "script_key")
                if type(v) == "string" then
                    credential = v
                    pcall(rawset, sc, "script_key", nil)
                    break
                end
            end
        end

        local spawn = member(task, "spawn")
        local fetch = member(host, "HttpGet")

        local ok, senv = pcall(function() return getfenv() end)
        if not ok or type(senv) ~= "table" then senv = globals end

        local ok2, environment = pcall(function() return getgenv() end)
        if not ok2 or type(environment) ~= "table" then environment = senv end

        local function global(key)
            return member(environment, key) or member(senv, key) or member(globals, key)
        end

        local sample = 20
        local platform = "?"
        pcall(function()
            local input = host:GetService("UserInputService")
            platform = (input.TouchEnabled and not input.KeyboardEnabled) and "m" or "d"
        end)

        local function ms(x) return math.floor(x * 1000 + .5) end

        -- Request transports
        local reqs, seen = {}, {}
        local function add(fn, name)
            if type(fn) == "function" and not seen[fn] then
                seen[fn] = true
                reqs[#reqs + 1] = { fn, name }
            end
        end
        add(global("request"),                       "request")
        add(global("http_request"),                  "http_request")
        add(global("httpRequest"),                   "httpRequest")
        add(global("httprequest"),                   "httprequest")
        add(member(global("http"), "request"),       "http.request")
        add(member(global("syn"),  "request"),       "syn.request")

        local bt = member(global("buffer"), "tostring")

        -- Endpoints
        local url      = "https://flowauth.net/assets/flowauth/sha256/8cb01d2dc57b8767d21e5e22139ffd72ee20dc0e30ce1401e15fb1df97b93cdd/v4_bootstrap_marberg.lua"
        local fallback = "https://37.187.136.187/assets/flowauth/sha256/8cb01d2dc57b8767d21e5e22139ffd72ee20dc0e30ce1401e15fb1df97b93cdd/v4_bootstrap_marberg.lua"
        local fresh    = url .. "?retry=121f7525d559dfdd"
        local retry    = gsub(url, "/sha256/[a-f0-9]+/", "/") .. "?retry=121f7525d559dfdd"

        local expected = 627508

        -- Download state
        local runtime, reason, issue, pr = nil, nil, "timed out", 0
        local transport, issueTransport = "HttpGet", "HttpGet"

        local function problem(message, rank)
            if rank >= pr then
                issue, pr, issueTransport = message, rank, transport
            end
        end

        local arrived, ck, cm = 0, 0, 0

        -- Validate and compile a downloaded body
        local function accept(value)
            local began = clock()

            if type(value) == "buffer" then
                local ok, text = pcall(bt, value)
                value = ok and text or nil
            end
            if type(value) ~= "string" then
                problem("unsupported response body", 1); return
            end

            if #value ~= expected then
                if #value < 1024 and find(value, "Failed to send HTTP request.", 1, true) then
                    problem(find(value, "timed out", 1, true)
                        and "HTTP request timed out" or "HTTP request failed", 2)
                else
                    problem("received " .. #value .. " bytes; expected " .. expected, 2)
                end
                return
            end

            -- Adler-32
            local s1, s2, i = 1.0, 0.0, 1
            while i + 7 <= #value do
                local a, b, c, d, e, f, g, h = byte(value, i, i + 7)
                s2 = (s2 + 8*s1 + 8*a + 7*b + 6*c + 5*d + 4*e + 3*f + 2*g + h) % 65521
                s1 = (s1 + a + b + c + d + e + f + g + h) % 65521
                i = i + 8
            end
            while i <= #value do
                s1 = (s1 + byte(value, i)) % 65521
                s2 = (s2 + s1) % 65521
                i = i + 1
            end
            if s2 * 65536.0 + s1 ~= 368677546 then
                problem("runtime checksum mismatch", 3); return
            end

            local t = clock(); ck = t - began

            local ok, compiled, detail = pcall(compile, value, "=FlowAuthRuntime")
            local text = not (ok and type(compiled) == "function")
                and tostring(ok and detail or compiled)

            -- One retry: Luau sometimes needs a beat after the fetch
            if text
                and not (find(text, "FlowAuthRuntime:") or find(text, "xpected") or find(text, "syntax")) then
                if wait then pcall(wait, 1.5) end
                ok, compiled, detail = pcall(compile, value, "=FlowAuthRuntime")
            end
            cm = clock() - t

            if ok and type(compiled) == "function" then
                runtime = compiled
                return true
            end
            reason = (ok and detail or compiled) or "compiler returned no function"
            issueTransport = transport
            return false
        end

        -- Candidate list
        local cs = { { fetch, "HttpGet", url } }
        if fallback ~= "" then cs[#cs + 1] = { fetch, "HttpGet", fallback, true } end
        for i = 1, #reqs do
            local candidate = reqs[i]
            if fallback ~= "" then
                cs[#cs + 1] = { candidate[1], candidate[2], fallback, true }
            end
            cs[#cs + 1] = { candidate[1], candidate[2], fresh }
        end
        cs[#cs + 1] = { fetch, "HttpGet", retry }

        local started, ni, ls, idle = clock(), 1, 0, 0
        local js, shut, alternate = {}, false, false
        local asynchronous = type(spawn) == "function" and type(wait) == "function"

        local function launch()
            local candidate = cs[ni]; ni = ni + 1; ls = clock()
            local job = { name = candidate[2], alternate = candidate[4] }
            js[#js + 1] = job

            local function run()
                if shut or job.started then return end
                job.started = true
                local ok, response
                if job.name == "HttpGet" then
                    ok, response = pcall(candidate[1], host, candidate[3])
                else
                    ok, response = pcall(candidate[1], { Url = candidate[3], Method = "GET" })
                end
                if not shut then job.ok, job.response, job.done = ok, response, true end
            end

            if asynchronous then
                local ok, thread = pcall(spawn, run)
                job.thread = ok and thread or nil
                if not job.started and type(job.thread) ~= "thread" then
                    asynchronous = false; run()
                end
            else
                run()
            end
        end

        launch()

        -- Poll loop: up to 4000 ticks, hard 40s wall clock
        for poll = 1, 4000 do
            local active, completed = 0, false
            for i = 1, #js do
                local job = js[i]
                if not job.done then
                    active = active + 1
                elseif not job.read then
                    job.read = true; completed = true
                    transport = job.name
                    arrived = clock() - started

                    local response = job.response; job.response = nil
                    if not job.ok then
                        problem("request failed", 1)
                    elseif type(response) == "table" then
                        local status = tonumber(
                            member(response, "StatusCode") or member(response, "status_code")
                            or member(response, "Status") or member(response, "status")
                        ) or 0
                        local success = member(response, "Success")
                        if success == nil then success = member(response, "success") end
                        if status == 0 and success == true  then status = 200 end
                        if success == false and status < 400 then status = 500 end

                        if status >= 200 and status < 300 then
                            accept(
                                member(response, "Body") or member(response, "body")
                                or member(response, "ResponseBody") or member(response, "response_body")
                            )
                        else
                            problem("HTTP " .. status, 2)
                        end
                    else
                        accept(response)
                    end

                    if runtime or reason then alternate = job.alternate; break end
                end
            end

            if runtime or reason or (active == 0 and ni > #cs) then break end

            local t = clock()
            if t - started - idle >= 40 then
                problem("HTTP download timed out after 40 seconds", 4); break
            end

            if ni <= #cs and (active == 0 or (active < 2 and (completed or t - ls >= 8))) then
                launch()
            elseif not pcall(wait, .03) then
                problem("HTTP download wait unavailable", 4); break
            else
                idle = idle + math.max(clock() - t - 1, 0)
            end
        end

        shut = true
        for i = 1, #js do js[i].response = nil end

        -- -----------------------------------------------------------
        -- Telemetry
        -- -----------------------------------------------------------
        local function send(base, path, body, delay)
            local query = "?p=" .. gsub(
                '{"protocol":3,'
                .. '"loader_hash":"f36125e051bd0b33a2ad9887c250f010",'
                .. '"launch_ticket":"v2:1r1KzpDEdOX9KgXy:amSqrQ5rfygYTXVFX7gPvQ:REE3W4oU6D-fb_at45ShTzl9fCUEdikCoTdD-dFC01PV6gHJXDUROUw5GQ1zTe3MNhoARYlBRCFjRaRhPJMciPo77mQ6nbvVDjQADR4dRMNMiX7LmERfs009aIK-r9zBNF3zTToT3n43jnK0Y_6tXGbYoSc0b9R651eQcAYZsTWAJUbIdkg039x3ejlyoIKPx7tBhmq3",'
                .. '"stage":"' .. body,
                "[^%w]",
                function(c) return string.format("%%%02X", byte(c)) end
            )

            pcall(spawn, function()
                if delay then pcall(wait, delay) end
                local target = gsub(base, "/assets/.*", path) .. query
                if not pcall(fetch, host, target) and reqs[1] then
                    pcall(reqs[1][1], { Url = target, Method = "GET" })
                end
            end)
        end

        -- -----------------------------------------------------------
        -- Failure path
        -- -----------------------------------------------------------
        if not runtime then
            pcall(function()
                local text = gsub(
                    issueTransport .. ": " .. tostring(reason or issue),
                    "[^%w .:;,()=/_-]", "?"
                )
                local body = (reason and "launcher_load" or "launcher_download")
                    .. '","executor":"launcher","diag":["pf=' .. platform .. '"],"error":"'
                    .. string.sub(text, 1, 160) .. '"}'

                for _, base in ipairs({ url, fallback }) do
                    if base ~= "" then send(base, "/v1/telemetry/executor", body) end
                end
            end)

            if reason then
                error("FlowAuth runtime compilation failed: " .. tostring(reason), 0)
            end
            error("FlowAuth runtime download failed (" .. issueTransport .. "): "
                .. tostring(issue) .. ". Please run the loader again.", 0)
        end

        -- 1-in-20 success telemetry
        if sample > 0 and spawn and math.random(sample) == 1 then
            pcall(send,
                alternate and fallback or url,
                "/v1/telemetry/load",
                'load","pf":"' .. platform
                .. '","tp":"' .. transport
                .. '","fb":' .. (alternate and 1 or 0)
                .. ',"tr":' .. #js
                .. ',"dl":' .. ms(arrived)
                .. ',"ck":' .. ms(ck)
                .. ',"cm":' .. ms(cm)
                .. ',"w":' .. sample .. '}',
                2)
        end

        if asynchronous then pcall(wait) end

        -- -----------------------------------------------------------
        -- _bsdata0 handoff (encrypted bootstrap payload)
        -- -----------------------------------------------------------
        local handoff = alternate
            and { "\20\224\48\247\115\156\139\237\204\136\21\124\93\97\134\215\165\188\54\119\13\251\34\175\241\150\239\40\14\42\176\250\124\201\161\20\106\125\158\123\46\16\148\198\248\50\196\71\77\126\203\102\229\58\228\180\215\225\1\117\117\136\208\20\6\132\229\112\5\162\10\194\151\191\205\179\172\18\10\185\2\201\171\111\199\156\242\77\42\234\158\143\77\22\99\175\30\56\210\206\229\102\233\9\7\248\42\94\100\113\14\252\57\187\187\93\116\15\107\65\20\180\74\35\172\182\106\231\194\121\78\43\205\224\199\5\95\184\113\25\105\211\50\17\20\7\201\155\83\144\138\227\197\182\210\133\151\197\57\204\52\34\51\38\238\128\151\36\149\108\174\151\54\91\19\59\255\6\113\228\205\31\13\225\79\171\215\44\215\18\173\10\128\83\97\35\218\239\156\59\134\33\97\128\131\66\33\210\176\0\11\248\147\125\200\232\37\35\76\20\240\209\53\244\247\183\218\4\65\72\132\197\214\52\207\81\157\180\50\146\249\190\15\166\9\114\11\237\89\229\254\19\237\20\176\41\215\99\61\188\255\41\63\46\74\225\117\73\117\247\62\184\155\122\159\77\165\32\235\133\190\96\26\203\19\41\27\113\255\160\124\175\23\33\181\219\219\35\238\30\4\157\252\172\27\51\46", 1815279946, 349462363 }
            or  { "\30\142\220\151\34\60\33\77\57\237\126\176\180\218\138\250\175\36\96\103\43\163\225\128\32\38\243\122\59\166\222\63\56\176\100\117\122\186\142\235\228\105\196\78\75\110\113\209\214\115\78\146\89\23\228\4\148\153\203\126\123\32\160\117\249\204\106\35\252\22\216\113\106\67\51\17\11\146\22\36\90\80\159\163\110\222\100\41\139\117\233\231\243\56\238\176\223\25\93\230\61\175\210\27\131\111\84\253\164\221\31\129\27\31\214\216\244\25\247\16\72\178\6\114\135\95\35\241\75\228\229\153\251\63\132\113\81\204\69\128\23\166\79\153\234\214\144\232\139\16\6\225\212\235\176\127\165\200\249\136\249\59\197\231\132\180\165\104\103\134\108\56\47\138\91\44\74\70\181\221\31\167\220\79\144\30\229\213\21\105\222\132\72\12\35\27\154\140\144\66\197\16\192\234\58\59\229\27\139\216\93\131\112\199\212\232\134\131\63\208\47\230\181\231\188\198\71\190\80\97\15\105\117\145\230\160\162\223\211\144\185\237\170\139\196\38\218\162\66\173\5\215\211\202\72\34\83\29\147\27\138\172\71\69\127\203\222\1\31\82\105\123\2\226\26\93\210\31\89\209\37\146\225\114\224\4\75\184\160\27\61\106\41\219\43\185\145\63\80\168\224\146\254\195\232", 4176930463, 64446826 }

        local function publish(target)
            if type(target) == "table" then
                pcall(rawset, target, "_bsdata0", handoff)
            end
        end

        publish(environment)
        publish(globals)
        _bsdata0 = handoff
        pcall(function() publish(getfenv(runtime)) end)
        handoff = nil

        return runtime(credential)
    end

    setEnvironment(run, scope)
    local result = pack(protect(run, ...))

    if not result[1] then
        if nativeProtectedRuntime or quiet == false
            or (authoredError ~= nil and authoredError == result[2]) then
            raise(result[2], 0)
        end
        return nil, result[2]
    end

    return unpackValues(result, 2, result.n)
end)(...)
