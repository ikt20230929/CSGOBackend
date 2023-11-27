using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.IdentityModel.Tokens;

namespace csgo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();
            var builder = WebApplication.CreateBuilder(args);
            Globals.Config = builder.Configuration.GetSection("Settings").Get<Config>();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = Globals.Config.BackendUrl,
                    ValidAudience = Globals.Config.BackendUrl,
                    IssuerSigningKey = Signing.AccessTokenKey,
                    RoleClaimType = "role",
                    NameClaimType = "name"
                };
            });
            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("API", policy =>
                {
                    policy.WithOrigins(Globals.Config.FrontendUrl);
                    policy.WithHeaders("content-type", "authorization");
                    policy.AllowCredentials();
                });
            });
            builder.Services.AddSwaggerGen();
            builder.Services.AddHttpLogging(o =>
            {
                o.LoggingFields = HttpLoggingFields.All;
            });
            builder.Services.AddControllersWithViews().AddNewtonsoftJson();

            var app = builder.Build();
            app.UseCors("API");
            app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseSwagger();
            app.UseSwaggerUI();
            app.MapControllers();
            app.UseSession();
            app.UseHttpLogging();
            app.Run();
        }
    }
}