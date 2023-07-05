---
title: 在 .Net 7 Web api 使用 JWT 驗證授權
sidebar_position: 10
sidebar_label: 在 .Net 7 Web api 使用 JWT
description: 在 .Net 7 Web api 使用 JWT 驗證授權
tags: [article, jwt, Net7]
draft: true
authors: H.J
---

## .Net 7 Webapi JWT Demo

之前在 Medium 的文章，已經有介紹過 JWT 概念，故這次重點直接放在 Net7 實作的程式碼，

* Medium 文章連結
[[C#] JSON Web Token(JWT)認證(authentication)授權(authorization)](https://medium.com/hans-revolution/c-json-web-token-jwt-%E8%AA%8D%E8%AD%89-authentication-%E6%8E%88%E6%AC%8A-authorization-409b5c000032)

這次使用的開發工具為Visual Studio 2022 for Mac，我們直接用 IDE 建立一個Ｗebapi專案
![建立專案](./Net7CreateSln.png) 
直接執行偵錯，就會看到 Swagger 頁面 裏頭只有一隻 WeatherForecast API，到這邊，代表我們 Web API 專案已經建立成功了！如下圖 
![Swagger 畫面](swagger.png)

但這時候還沒有驗證的機制，所以接下來我們開始今天的重點！主要分為以下幾個重點

1. 建立`產生＆驗證 JWT Token`的方法
   * 主要用於產生＆驗證JWT Token是否有效
2. 建立 User 測試資料以及 User 登入API
3. 建立`JwtMiddleware`  
   * 每當有 Request 帶 JWT Token 進 API 時，就會先驗證JWT Token 是否有效，並將解析後的Claims存入Context
4. 建立`AuthorizeAttribute`
   * 讓需要授權的 Controller 掛上這個 Attribute 之後，才擁有存取的權限
5. 測試 Jwt 驗證授權

### 建立`產生＆驗證 JWT Token`的方法

```csharp title="Authorization/JwtUtils.cs" showLineNumbers
        public string GenerateJwtToken(User user)
        {
            // generate token that is valid for 7 days
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret!);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", user.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public int? ValidateJwtToken(string? token)
        {
            if (token == null)
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret!);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

                // return user id from JWT token if validation successful
                return userId;
            }
            catch
            {
                // return null if validation fails
                return null;
            }
        }
```

### 建立 User 測試資料以及 User 登入API

首先我們建立 User 的 DataModel，這部分就是新增一個 User class 僅此而已！

``` csharp title="Entities/User.cs" showLineNumbers
    public class User
    {
        public int Id { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Username { get; set; }

        [JsonIgnore]
        public string? Password { get; set; }
    }
```

實務上 User資料應該要來自資料庫，但我們這次重點在於JWT驗證授權，所以我們用 hardcode 的方式直接建立 User 假資料，
如程式碼 13~15 行我們新增了三筆假資料，接著建立 Authenticate 方法，目的在驗證我們傳入的帳號密碼，是否有在我們的假資料裡面．

``` csharp title="Services/UserService.cs" showLineNumbers
   public interface IUserService
    {
        AuthenticateResponse? Authenticate(AuthenticateRequest model);
        IEnumerable<User> GetAll();
        User? GetById(int id);
    }

    public class UserService : IUserService
    {
        // users hardcoded for simplicity, store in a db with hashed passwords in production applications
        private List<User> _users = new List<User>
    {
        // highlight-start
        new User { Id = 1, FirstName = "User01", LastName = "User01", Username = "test", Password = "test" },
        new User { Id = 2, FirstName = "User02", LastName = "User02", Username = "test02", Password = "test" },
        new User { Id = 3, FirstName = "User03", LastName = "User03", Username = "test03", Password = "test" }
        // highlight-end
    };

        private readonly IJwtUtils _jwtUtils;

        public UserService(IJwtUtils jwtUtils)
        {
            _jwtUtils = jwtUtils;
        }

        public AuthenticateResponse? Authenticate(AuthenticateRequest model)
        {
            var user = _users.SingleOrDefault(x => x.Username == model.Username && x.Password == model.Password);

            // return null if user not found
            if (user == null) return null;

            // authentication successful so generate jwt token
            var token = _jwtUtils.GenerateJwtToken(user);

            return new AuthenticateResponse(user, token);
        }

        public IEnumerable<User> GetAll()
        {
            return _users;
        }

        public User? GetById(int id)
        {
            return _users.FirstOrDefault(x => x.Id == id);
        }
    }

```

接下來我們要建立 User 登入的 API，直接建立 UserController，內容如下，
共有兩隻API

* `Authenticate` 用來驗證User
* `GetAll` 取得所有User資料(需要授權)

```csharp title="Controller/UserController.cs" showLineNumbers
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate(AuthenticateRequest model)
        {
            var response = _userService.Authenticate(model);

            if (response == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            return Ok(response);
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }
    }

```


### 建立`JwtMiddleware`  

重點程式碼 12~18 行
JwtMiddleware 擷取到 Header 中的 Authorization Bearer Token 時，就使用我們第一步驟創建的 ValidateToken 方法，
驗證 Token 有效之後，就會把 UserId 存入 Context 之中．

```csharp title="Authorization/JwtMiddleware.cs" showLineNumbers
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context, IUserService userService, IJwtUtils jwtUtils)
        { 
            // highlight-start
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            var userId = jwtUtils.ValidateJwtToken(token);
            if (userId != null)
            {
                // attach user to context on successful jwt validation
                context.Items["User"] = userService.GetById(userId.Value);
            }
            // highlight-end
            await _next(context);
        }
    }
```

### 建立`AuthorizeAttribute`

這邊我們實作 `AuthorizeAttribute` 繼承了 Attribute, IAuthorizationFilter，
在這邊主要接續我們上一步驟在 JwtMiddleware 裡面，當 User 有帶入JWT Token並且驗證成功，就會把 User 登入資訊存入 context 之中，
然後 OnAuthorization 方法就可以取出 context 裡面的 User 資訊，判斷是否有權限可以使用 API

```csharp title="Authorization/AuthorizeAttribute.cs" showLineNumbers
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            // skip authorization if action is decorated with [AllowAnonymous] attribute
            var allowAnonymous = context.ActionDescriptor.EndpointMetadata.OfType<AllowAnonymousAttribute>().Any();
            if (allowAnonymous)
                return;

            // authorization
            var user = (User?)context.HttpContext.Items["User"];
            if (user == null)
            {
                // not logged in or role not authorized
                context.Result = new JsonResult(new { message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized };
            }
        }
    }
```

### 測試 Jwt 驗證授權

我們將寫好的程式 Run 起來，會看到我們剛剛新增的 Users API 已經在 Swagger Ui 列表上面了
![Test Jwt](Net7TestJwt.png)

我們使用 Postman 來測試 API

* 直接呼叫 Users，會發現 API 回傳 `401 Unauthorized` 因為我們還沒有經過授權，所以被擋了下來！
![Login401](Login401.png)

* 模擬一下呼叫 Users/authenticate 來做登入，API 回傳 200 並將 Jwt Token 回傳給我們
![Login200](Login200.png)

* 現在將 Jwt Token 放入Header中的 Bearer Token ，在呼叫一次 Users，會發現 API 回傳 200 並且將我們建立的假資料成功回傳！
![GetUserOk](GetUserOk.png)

### 總結

雖然 Microsoft 團隊針對專案的 JWT 設定優化了許多，使得新專案在設定使用 JWT 驗證的流程變得簡單許多，但實務上還是有許多要客製化的部分，
所以這在邊我們從頭開始用 .Net 7 建立 WebAPI 新專案，並實作 Middleware 及 Attribute， 讓 JWT 驗證授權掌握在自己手中，也方便我們客製化．

在實務建議以下幾點事項：

1. JWT Secret Key 建議隨機亂數產生，網路上有許多免費的ㄒ GUID Generator 可以直接使用！
2. 授權建議使用 Role-Base 做 API 的角色權限控管，避免所有人登入之後權限都一樣．
3. JWT Token 容易被拆解，如果有機敏資料，不應該存在 JWT 的 Payload 之中．
4. 如果可以 產出的 JWT Token 建議在多一層加密，避免 Payload 被拆解拿去做其他事情．

#### GitHub 連結

[Net7Jwt](https://github.com/oneal32xx/Net7Jwt/)

#### 參考

* [How-to-use-JWT-token-based-auth-in-aspnet-core-60](https://blog.miniasp.com/post/2022/02/13/
How-to-use-JWT-token-based-auth-in-aspnet-core-60)
* [Authentication and authorization in minimal APIs](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/minimal-apis/security?view=aspnetcore-7.0)
* [Authentication samples for ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/samples?view=aspnetcore-7.0)
