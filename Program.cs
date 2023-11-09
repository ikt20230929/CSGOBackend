using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace csgo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = "https://localhost:7233",
                    ValidAudience = "https://localhost:7233",
                    IssuerSigningKey = Signing.AccessTokenKey
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
                    policy.WithOrigins("http://localhost:3000");
                    policy.WithHeaders("content-type", "authorization");
                });
            });

            builder.Services.AddSwaggerGen();
            builder.Services.AddControllersWithViews().AddNewtonsoftJson();

            var app = builder.Build();
            app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCors("API");
            app.UseSwagger();
            app.UseSwaggerUI();
            app.MapControllers();
            app.UseSession();
            app.Run();
        }
    }
}