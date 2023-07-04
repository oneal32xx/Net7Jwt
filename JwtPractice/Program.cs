using JwtPractice.Authorization;
using JwtPractice.Helper;
using JwtPractice.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.OpenApi.Models;
using Microsoft.IdentityModel.JsonWebTokens;
using System.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddCors();
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// configure strongly typed settings object
builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));
// configure DI for application services
builder.Services.AddScoped<IJwtUtils, JwtUtils>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddSwaggerGen(c=>{
    c.CustomSchemaIds(x => x.FullName);
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "請輸入 jwt Token",
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme{
            Reference = new OpenApiReference{
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer",
             }
            },
            new string[] { }
        } 
    });

});

//builder.Services
//    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    .AddJwtBearer(options =>
//    {
//        // 當驗證失敗時，回應標頭會包含 WWW-Authenticate 標頭，這裡會顯示失敗的詳細錯誤原因
//        options.IncludeErrorDetails = true; // 預設值為 true，有時會特別關閉

//        options.TokenValidationParameters = new TokenValidationParameters
//        {
//            // 透過這項宣告，就可以從 "sub" 取值並設定給 User.Identity.Name
//            NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
//            // 透過這項宣告，就可以從 "roles" 取值，並可讓 [Authorize] 判斷角色
//            RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",

//            // 一般我們都會驗證 Issuer
//            //ValidateIssuer = true,
//            //ValidIssuer = Configuration.GetValue<string>("JwtSettings:Issuer"),
//            ValidateIssuer = false,

//            // 通常不太需要驗證 Audience
//            ValidateAudience = false,
//            //ValidAudience = "JwtAuthDemo", // 不驗證就不需要填寫

//            // 一般我們都會驗證 Token 的有效期間
//            ValidateLifetime = true,

//            // 如果 Token 中包含 key 才需要驗證，一般都只有簽章而已
//            ValidateIssuerSigningKey = false,

//            // "1234567890123456" 應該從 IConfiguration 取得
//            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetSection("AppSettings").Get<AppSettings>().Secret))
//        };
//    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

//app.UseAuthentication();
app.UseAuthorization();

// global cors policy
app.UseCors(x => x
    .AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader());

// custom jwt auth middleware
app.UseMiddleware<JwtMiddleware>();
app.MapControllers();

app.Run();

