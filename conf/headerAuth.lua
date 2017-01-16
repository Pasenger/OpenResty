require "cjson"

-- 设置Response的Content-Type
ngx.header.content_type = 'application/json';

-- 获取HTTP Headers
local headers = ngx.req.get_headers()

-- 获取需要验证的HTTP Headers
local vendor = headers["G-SERVICE-VENDOR"]
local model = headers["G-SERVICE-MODEL"]
local appKey = headers["G-SERVICE-APPKEY"]
local accessToken = headers["G-ACCESS-TOKEN"]

local remoteAddr = ngx.var.remote_addr

-- 验证G-SERVICE-VENDOR
if("GCKS" ~= vendor) then
	ngx.say(cjson.encode({code = "ERROR-1001", message = "G-SERVICE-VENDOR is not support"}))
	return
end

-- 验证G-SERVICE-MODEL、G-SERVICE-APPKEY、G-ACCESS-TOKEN

local redis = require "resty.redis"
local redis = redis:new()

-- 设置Redis超时时间, 单位：ms
redis:set_timeout(1000)

-- 连接Redis
local ok, err = redis:connect("127.0.0.1", 6379)
if not ok then	-- Redis连接失败，直接放过
    return
end

-- 查询AccessToken
cacheToken, err = redis:get("WiFi::3ATPL::ACCESSTOKEN::"..appKey.."::"..remoteAddr)
if (not cacheToken or cacheToken == ngx.null) then	--查询失败
    ngx.say(cjson.encode({code = "ERROR-2001", message = "G-ACCESS-TOKEN is invalid."}))
    return
end

-- 查询成功后和HTTP Header中的accessToken比对
local tokenObj = cjson.decode(cacheToken)
if(accessToken == tokenObj["token"]["accessToken"]) then	-- 一致： 验证通过
	-- ngx.say(cjson.encode({code = "0", message = "OK"}));
	return
end

-- 不一致： 验证失败
ngx.say(cjson.encode({code = "ERROR-2002", message = "G-ACCESS-TOKEN is invalid."}))



