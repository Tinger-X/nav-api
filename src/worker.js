///////////////////////////////////// 配置区 /////////////////////////////////////
const Config = {
  // ↓↓↓↓↓↓ 建议全部修改 ↓↓↓↓↓↓
  front: "*",  // 前端Pages绑定的域名，用于限制请求
  token_name: "Tin-Nav-Token",  // 鉴权时header中的token
  admin: "admin",  // 管理员用户名
  init_auth: "<your-auth-code>",  // /init?auth=初始化授权码
  // ↓↓↓↓↓↓ 可以不修改 ↓↓↓↓↓↓
  max_retry: 5,  // 每分钟密码错误次数超过max_retry则不再验证密码正确性，直接拒绝登录
  max_hack: 10,  // 每分钟密码错误次数超过max_hack则将该ip拉入黑名单
  token_size: 16,  // token长度
  hash_seed: 217,  // hash函数随机种子
  hash_size: 16,  // hash函数结果位数
  kv_db: this["TinNav"],  // 绑定的KV名称
  init_detail: [  // 初始化时，绑定到管理员用户的快捷方式详情，block列表
    [  // 单个block
      [0, "基础工具"],  // 该block[是否折叠, block名称]，除首项外的其它项为快捷方式详情
      ["在线PS", "https://ps.gaoding.com/", "https://www.uupoop.com/favicon.ico"],  // 名称、地址、icon地址
      ["ProcessOn", "https://www.processon.com/diagrams", "https://www.processon.com/favicon.ico"],
      ["极简壁纸", "https://bz.zzzmh.cn/index", "https://bz.zzzmh.cn/favicon.ico"],
      ["IconFont", "https://www.iconfont.cn/", "https://img.alicdn.com/imgextra/i2/O1CN01ZyAlrn1MwaMhqz36G_!!6000000001499-73-tps-64-64.ico"],
      ["非凡资源", "https://cj.ffzyapi.com/", "https://cj.ffzyapi.com/template/default/img/favicon.png"],
      ["文本转语音", "https://www.text-to-speech.cn/", "https://www.text-to-speech.cn/img/speech.png"]
    ]
  ]
};

const Prefix = {
  user: "_NANE_",  // $user$username: {pass, token}, 用以登录鉴权
  token: "_TOKEN_",  // $token$real-token: $links, 用以直接操作links
  ip: "_IP_",  // $ip$real-ip: $times, 用以记录ip敏感操作频次，超出$Config.hack则封禁该ip
  login: "_LOGIN_",  // $login$username: $times, 用以记录某ip下某用户的登录频次，超出$Config.hack则封禁该ip
  hack: "_HACK_"  //$hack: $ip-list, 用以记录被封禁的ip列表
};


///////////////////////////////////// 基础函数区，无需上下文 /////////////////////////////////////
const BaseStr = "zxcvbnmlkjhgfdsaqwertyuiop0.123456789-ZXCVBNMLKJHGFDSAQWERTYUIOP_";

const randomString = size => {
  let result = "";
  for (let i = 0; i < size; i++) {
    result += BaseStr.charAt(Math.floor(Math.random() * BaseStr.length));
  }
  return result;
}

const restfulResponse = (code, data, msg) => {
  // const payload = JSON.stringify({ code: code, data: data, msg: msg });
  // const resp = new Response(payload);
  const resp = Response.json({ code: code, data: data, msg: msg })
  resp.headers.set("Access-Control-Allow-Origin", Config.front);
  resp.headers.set("Access-Control-Allow-Methods", "GET,POST");
  return resp;
}

const sha128 = plain => {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hash = new Uint8Array(Config.hash_size);
  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    for (let j = 0; j < Config.hash_size; j++) {
      hash[j] = (hash[j] + ((byte ^ (j * 7) ^ Config.hash_seed) + (i * 11) + data.length)) % 256;
    }
  }
  for (let k = 0; k < Config.hash_size; k++) {
    hash[k] = (hash[k] * Config.hash_seed + (k * 3)) % 256;
  }
  let res = "";
  for (let i = 0; i < hash.length; i++) {
    const hex = hash[i].toString(16).padStart(2, "0");
    res += hex;
  }
  return res;
}


///////////////////////////////////// 协助函数区，需要上下文 /////////////////////////////////////
const Ctx = {  // 上下文共享变量
  ip: "",
  method: "",
  token: null,
  blocked: new Set(),
  params: {},
  request: {},
  path: ""
};

async function getIpLoginTimes(user) {
  const ip_times = await getKV(`${Prefix.ip}${Ctx.ip}`) || 0;
  const login_times = await getKV(`${Prefix.login}${user}`) || 0;
  return { ip: ip_times, login: login_times };
}

async function blockIp() {
  Ctx.blocked.add(Ctx.ip);
  await setKV(`${Prefix.hack}`, Array.from(Ctx.blocked));
}

async function increaseIpDubious(current) {
  if (current < Config.max_hack) {
    await setKV(`${Prefix.ip}${Ctx.ip}`, current + 1, { expirationTtl: 60 });
  } else {
    await blockIp();
  }
}

async function increaseUserDubious(user, current) {
  if (current < Config.max_hack) {
    await setKV(`${Prefix.login}${user}`, current + 1, { expirationTtl: 60 });
  } else {
    await blockIp();
  }
}

async function getKV(key, option = {}) {
  if (!option.hasOwnProperty("type")) {
    option.type = "json";
  }
  return await Config.kv_db.get(key, option);
}

async function setKV(key, value, option = {}) {
  if ("string" !== typeof value) {
    value = JSON.stringify(value);
  }
  await Config.kv_db.put(key, value, option);
}

async function authBeforeAction(strict, action) {
  if (Ctx.token === null) {
    if (strict) {
      return restfulResponse(400, null, "参数错误");
    }
    const admin = await getKV(`${Prefix.user}${Config.admin}`);
    Ctx.token = admin.token;
  }
  const detail = await getKV(`${Prefix.token}${Ctx.token}`);
  if (detail === null) {
    return restfulResponse(400, null, "鉴权失败");
  }
  return action(detail);
}


///////////////////////////////////// 相关内容搜索 /////////////////////////////////////
const EnginesMap = { baidu: _fetchBaiduRelate, bing: _fetchBingRelate, google: _fetchGoogleRelate };
const UserAgentHeader = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
};  // user-agent-header

async function _fetchBaiduRelate(query) {
  const url = `https://www.baidu.com/sugrec?prod=pc&wd=${query}`;
  try {
    const resp = await fetch(url, { method: "GET", headers: UserAgentHeader });

    if (!resp.ok) {
      return restfulResponse(resp.status, null, resp.statusText);
    }
    const data = await resp.json();
    const payload = data.g.map(itr => itr.q);
    return restfulResponse(200, payload, "成功");
  } catch (error) {
    return restfulResponse(500, null, "服务发生错误");
  }
}

async function _fetchBingRelate(query) {
  const url = `https://cn.bing.com/AS/Suggestions?csr=1&cvid=${randomString(16)}&qry=${query}`;
  try {
    const resp = await fetch(url, { method: "GET", headers: UserAgentHeader });

    if (!resp.ok) {
      return restfulResponse(resp.status, null, resp.statusText);
    }
    const data = await resp.json();
    const payload = data.s.map(itr => itr.q.replace(/|/g, ""));
    return restfulResponse(200, payload, "成功");
  } catch (error) {
    return restfulResponse(500, null, "服务发生错误");
  }
}

async function _fetchGoogleRelate(query) {
  const url = `https://www.google.com/complete/search?client=gws-wiz&q=${query}`;
  try {
    const resp = await fetch(url, { method: "GET", headers: UserAgentHeader });

    if (!resp.ok) {
      return restfulResponse(resp.status, null, resp.statusText);
    }
    const data = (await resp.text()).trim().slice(19, -1);
    const payload = JSON.parse(data)[0].map(itr => itr[0]);
    return restfulResponse(200, payload, "成功");
  } catch (error) {
    return restfulResponse(500, null, "服务发生错误");
  }
}

async function handleRealte() {
  if (Ctx.method === "POST") {
    return restfulResponse(400, null, "请求方法错误");
  }
  const engine = Ctx.params.get("engine"), query = Ctx.params.get("query")?.trim();
  if (query === null || query === "" || !EnginesMap.hasOwnProperty(engine)) {
    return restfulResponse(400, null, "参数错误");
  }
  return EnginesMap[engine](query);
}


///////////////////////////////////// 用户功能区 /////////////////////////////////////
async function _handleUserLogin() {
  if (Ctx.method === "GET") {
    return restfulResponse(400, null, "请求方法错误");
  }

  const payload = await Ctx.request.json();
  if (!payload.hasOwnProperty("name") || !payload.hasOwnProperty("pass")) {
    return restfulResponse(400, null, "参数错误");
  }
  const current = await getIpLoginTimes(payload.name);
  if (current.ip > Config.max_retry || current.login > Config.max_retry) {
    await increaseIpDubious(current.ip);
    await increaseUserDubious(payload.name, current.login);
    return restfulResponse(400, null, "请求过量警告");
  }

  const user = await getKV(`${Prefix.user}${payload.name}`);
  if (user === null || user.pass !== payload.pass) {
    await increaseIpDubious(current.ip);
    await increaseUserDubious(payload.name, current.login);
    return restfulResponse(400, null, "用户名或密码错误");
  }

  return restfulResponse(200, user.token, "成功");
}

async function _handleUserRegister() {
  if (Ctx.method === "GET") {
    return restfulResponse(400, null, "请求方法错误");
  }

  const ip_times = await getKV(`${Prefix.ip}${Ctx.ip}`) || 0;
  if (ip_times > Config.max_retry) {
    await increaseIpDubious(ip_times);
    return restfulResponse(400, null, "请求过量警告");
  }
  const user = await Ctx.request.json();
  if (!user.hasOwnProperty("name") || !user.hasOwnProperty("pass")) {
    return restfulResponse(400, null, "参数错误");
  }
  const name = user.name;
  if (await getKV(`${Prefix.user}${name}`) !== null) {
    await increaseIpDubious(ip_times);
    return restfulResponse(400, null, "用户已注册");
  }
  user.token = randomString(Config.token_size);
  for (; ;) {
    if (await getKV(`${Prefix.token}${user.token}`) === null) {
      break;
    }
    user.token = randomString(Config.token_size);
  }
  delete user.name;
  await setKV(`${Prefix.user}${name}`, user);
  await setKV(`${Prefix.token}${user.token}`, "[]");
  await increaseIpDubious(ip_times);
  return restfulResponse(200, user.token, "成功");
}

async function handleUser() {
  if (Ctx.path.startsWith("/login")) {
    return _handleUserLogin();
  } else if (Ctx.path.startsWith("/register")) {
    return _handleUserRegister();
  }
  return restfulResponse(400, null, "接口不存在");
}


///////////////////////////////////// 快捷方式区 /////////////////////////////////////
async function _handleLinksDetail(detail) {
  return restfulResponse(200, detail, "成功");
}

async function _handleLinksCollapse(detail) {
  return restfulResponse(500, detail, "开发中");
}

async function _handleAddBlock(detail) {
  return restfulResponse(500, detail, "开发中");
}

async function _handleRenameBlock(detail) {
  return restfulResponse(500, detail, "开发中");
}

async function _handleDeleteBlock(detail) {
  return restfulResponse(500, detail, "开发中");
}

async function _handleRankBlock(detail) {
  return restfulResponse(500, detail, "开发中");
}

async function _handleAddLink(detail) {
  return restfulResponse(500, detail, "开发中");
}

async function _handleModifyLink(detail) {
  return restfulResponse(500, detail, "开发中");
}

async function _handleDelteLink(detail) {
  return restfulResponse(500, detail, "开发中");
}

async function _handleRankLink(detail) {
  // TODO: 跨block排序
  return restfulResponse(500, detail, "开发中");
}

async function handleLinks() {
  if (Ctx.path.startsWith("/detail")) {
    if (Ctx.method === "POST") {
      return restfulResponse(400, null, "请求方法错误");
    }
    return authBeforeAction(false, _handleLinksDetail);
  }
  if (Ctx.method === "GET") {
    return restfulResponse(400, null, "请求方法错误");
  } else if (Ctx.path.startsWith("/collapse")) {
    return authBeforeAction(true, _handleLinksCollapse);
  } else if (Ctx.path.startsWith("/addBlock")) {
    return authBeforeAction(true, _handleAddBlock);
  } else if (Ctx.path.startsWith("/renameBlock")) {
    return authBeforeAction(true, _handleRenameBlock);
  } else if (Ctx.path.startsWith("/deleteBlock")) {
    return authBeforeAction(true, _handleDeleteBlock);
  } else if (Ctx.path.startsWith("/rankBlock")) {
    return authBeforeAction(true, _handleRankBlock);
  } else if (Ctx.path.startsWith("/addLink")) {
    return authBeforeAction(true, _handleAddLink);
  } else if (Ctx.path.startsWith("/modifyLink")) {
    return authBeforeAction(true, _handleModifyLink);
  } else if (Ctx.path.startsWith("/delteLink")) {
    return authBeforeAction(true, _handleDelteLink);
  } else if (Ctx.path.startsWith("/rankLink")) {
    return authBeforeAction(true, _handleRankLink);
  }
  return restfulResponse(400, null, "接口不存在");
}


///////////////////////////////////// 系统初始化 /////////////////////////////////////
async function handleInit() {
  if (Ctx.method === "POST") {
    return restfulResponse(400, null, "请求方法错误");
  }

  const ip_times = await getKV(`${Prefix.ip}${Ctx.ip}`) || 0;
  if (ip_times > Config.max_retry) {
    await increaseIpDubious(ip_times);
    return restfulResponse(400, null, "请求过量警告");
  }
  if (Ctx.params.get("auth") !== Config.init_auth) {
    await increaseIpDubious(ip_times);
    return restfulResponse(400, null, "鉴权失败");
  }
  const pass = Ctx.params.get("pass");
  if (pass === null) {
    return restfulResponse(400, null, "参数错误");
  }
  if (await getKV(`${Prefix.user}${Config.admin}`) !== null) {
    await increaseIpDubious(ip_times);
    return restfulResponse(400, null, "用户已注册");
  }
  const user = {
    pass: sha128(`${Config.admin}-${pass}`),
    token: randomString(Config.token_size)
  }

  await setKV(`${Prefix.user}${Config.admin}`, user);
  await setKV(`${Prefix.token}${user.token}`, Config.init_detail);
  return restfulResponse(200, {
    user: "amdin",
    pass: pass,
    token: user.token,
    detail: Config.init_detail
  }, "成功");
}


addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);

  Ctx.request = request;
  Ctx.ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "1.1.1.1";
  Ctx.method = request.method;
  Ctx.path = url.pathname;
  Ctx.params = url.searchParams;
  Ctx.token = request.headers.get(Config.token_name);

  event.respondWith(handleRequest());
});

async function handleRequest() {
  Ctx.blocked = new Set(await getKV(`${Prefix.hack}`) || []);
  if (Ctx.blocked.has(Ctx.ip)) {
    return restfulResponse(400, Ctx.ip, "IP被封禁");
  }

  if (Ctx.path.startsWith("/relate")) {
    return handleRealte();
  } else if (Ctx.path.startsWith("/links")) {
    Ctx.path = Ctx.path.substring(6);
    return handleLinks();
  } else if (Ctx.path.startsWith("/user")) {
    Ctx.path = Ctx.path.substring(5);
    return handleUser();
  } else if (Ctx.path.startsWith("/init")) {
    return handleInit();
  }
  return restfulResponse(400, Ctx.ip, "接口不存在");
}
