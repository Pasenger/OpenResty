-- 获取accessToken

-- "WiFi::ACCESSTOKEN::"..appKey.."::"..model.."::"..remoteAddr

-- 设置Response的Content-Type
ngx.header.content_type = 'application/json';

-- 验证appkey, model, remoteAddr
local remoteAddr = ngx.var.remote_addr

local cjson = require "cjson"

local result = {}
result["message"] = "OK"
result["code"] = "0"

-- 设置读取body
ngx.req.read_body()

-- 获取application/x-www-form-urlencoded参数
local args, err = ngx.req.get_post_args()
if not args then
	result["message"] = "Args is null."
	result["code"] = "ERROR-3000"

	local output = cjson.encode(result)
    -- ngx.log("get accessToken result: ip: "..remoteAddr..", result: "..output)
    ngx.say(output)
	return
end

-- appKey
local appKey = args["appKey"]

-- appSecret
local appSecret = args["appSecret"]

-- 从redis获取
local redis = require "resty.redis"
local redis = redis:new()

-- 设置Redis超时时间, 单位：ms
redis:set_timeout(1000)

-- 连接Redis
local ok, err = redis:connect("127.0.0.1", 6379)
if ok then	-- Redis连接成功，直接放过
	ok, err = redis:get("WiFi::3ATPL::ACCESSTOKEN::"..appKey.."::"..remoteAddr)
	if (ok and ok ~= ngx.null) then	--命中缓存
		-- ngx.log("get accessToken by cache result: ip: "..remoteAddr..", result: "..ok)
		ngx.say(ok)
	    return
	end
end

local mysql = require "resty.mysql"
local db, err = mysql:new()
if not db then
    result["message"] = "Service not available"
	result["code"] = "ERROR-3001"

	local output = cjson.encode(result)
    -- ngx.log("get accessToken result: ip: "..remoteAddr..", result: "..output)
    ngx.say(output)
    return
end

db:set_timeout(1000) -- 1 sec

local ok, err, errcode, sqlstate = db:connect {
    host = "10.8.122.70",
    port = 4006,
    database = "wifi_plt_apps",
    user = "rw",
    password = "123456",
    max_packet_size = 1024 * 10240
}

if not ok then
	result["message"] = "Service not available."
	result["code"] = "ERROR-3002"

	local output = cjson.encode(result)
    -- ngx.log("get accessToken result: ip: "..remoteAddr..", result: "..output)
    ngx.say(output)
    return
end

-- 根据remoteAddr查询app信息
res, err, errcode, sqlstate = db:query("select app.app_key, app.app_secret from s_app app, s_ip_allow ipa where ipa.ip = '"..remoteAddr.."' and ipa.app_key = '"..appKey.."' and app.app_key = ipa.app_key", 1)
if not res then	-- 未查询到结果
    result["message"] = "Service not available."
	result["code"] = "ERROR-3003"

	local output = cjson.encode(result)
    -- ngx.log("get accessToken result: ip: "..remoteAddr..", result: "..output..", errcode: "..errcode..", err"..err)
    ngx.say(output)
    return
end

local ok, err = db:set_keepalive(10000, 100)
if not ok then
    -- ngx.log("failed to set mysql keepalive: ", err)
    -- return
end

-- ngx.say(res[1]["app_secret"])

if(res[1]["app_secret"] ~= appSecret) then	-- appSecret错误
	result["message"] = "SAppSecret is invalid."
	result["code"] = "ERROR-3004"

	local output = cjson.encode(result)
    -- ngx.log("get accessToken result: ip: "..remoteAddr..", result: "..output..", errcode: "..errcode..", err"..err)
    ngx.say(output)

	return
end

-- 验证通过，生成AccessToken
math.randomseed(tostring(os.time()):reverse():sub(1, 9))
local randomNum = math.random(10000000,99999999)
local accessToken = ngx.md5(appKey..appSecret..randomNum..remoteAddr..appSecret)

local token = {}
token["accessToken"] = accessToken
token["expire"] = os.date("%Y-%m-%d %H:%M:%S", os.time() + 7200)

result["message"] = "OK"
result["code"] = "0"
result["token"] = token

local output = cjson.encode(result)

-- 保存缓存
ok, err = redis:setex("WiFi::3ATPL::ACCESSTOKEN::"..appKey.."::"..remoteAddr, 7200, output)
if not ok then
	-- ngx.log("failed to save accessToken cache to redis: ", err)
	-- return
end

local ok, err = redis:set_keepalive(10000, 100)
if not ok then
    -- ngx.log("failed to set redis keepalive: ", err)
    -- return
end

-- ngx.log("get accessToken result: ip: "..remoteAddr..", result: "..output)

ngx.say(output)
