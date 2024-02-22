using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using csgo.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace csgo
{
    /// <summary>
    /// A Program osztály.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Az alkalmazás fő belépési pontja.
        /// </summary>
        /// <param name="args">Parancssori argumentumok</param>
        public static void Main(string[] args)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();
            var builder = WebApplication.CreateBuilder(args);
            Globals.Config = builder.Configuration.GetSection("Settings").Get<Config>() ?? throw new Exception("Failed to load config, make sure appsettings.json exists.");
            builder.Services.AddDbContext<CsgoContext>();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = Globals.Config.BackUrl,
                    ValidAudience = Globals.Config.BackUrl,
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
                    policy.WithOrigins(Globals.Config.FrontUrl);
                    policy.WithHeaders("content-type", "authorization");
                    policy.AllowCredentials();
                });
            });
            builder.Services.AddSwaggerGen(option =>
            {
                option.SwaggerDoc("v1", new OpenApiInfo { Title = "CSGO Backend API", Version = "v1" });
                option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please enter a valid token",
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    BearerFormat = "JWT",
                    Scheme = "Bearer"
                });
                option.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type=ReferenceType.SecurityScheme,
                                Id="Bearer"
                            }
                        },
                        Array.Empty<string>()
                    }
                });
                
                var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                option.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
            });
            builder.Services.AddHttpLogging(o =>
            {
                o.LoggingFields = HttpLoggingFields.All;
            });
            builder.Services.AddControllersWithViews().AddNewtonsoftJson();

            var app = builder.Build();
            using (var serviceScope = app.Services.CreateScope())
            {
                var context = serviceScope.ServiceProvider.GetRequiredService<CsgoContext>();
                context.Database.EnsureCreated();
            }
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

