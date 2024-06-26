using csgo.Jobs;
using csgo.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Quartz;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using Serilog;
using Swashbuckle.AspNetCore.SwaggerGen;
using csgo.Services;
using csgo.Data;

namespace csgo
{
    /// <summary>
    /// Segédosztály arra, hogy a Fido2NetLib névtérbeli osztályok ne jelenjenek meg a Swagger dokumentációban.
    /// </summary>
    public class ExcludeFido2NetLibSchemas : ISchemaFilter
    {
        /// <summary>
        /// A Fido2NetLib névtérbeli osztályok kiszűrése a Swagger dokumentációból.
        /// </summary>
        public void Apply(OpenApiSchema schema, SchemaFilterContext context)
        {
            var keys = new List<string>();
            foreach(var key in context.SchemaRepository.Schemas.Keys)
            {
                if (key.Contains("Fido2NetLib") || key.StartsWith("Microsoft"))
                {
                    keys.Add(key);
                }
            }

            foreach(var key in keys)
            {
                context.SchemaRepository.Schemas.Remove(key);
            }

            if (schema.Properties.ContainsKey("webAuthnAssertionResponse"))
            {
                schema.Properties.Remove("webAuthnAssertionResponse");
            }
        }
    }

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
            var uploadsPath = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
            
            if (!Directory.Exists(uploadsPath))
            {
                Directory.CreateDirectory(uploadsPath);
            }

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();
            var builder = WebApplication.CreateBuilder(args);
            Globals.Config = builder.Configuration.GetSection("Settings").Get<Config>() ?? throw new Exception("Failed to load config, make sure appsettings.json exists.");
            builder.Host.UseSerilog((context, configuration) => configuration.ReadFrom.Configuration(context.Configuration));
            builder.Services.AddScoped<ICaseItemRepository, CaseItemRepository>();
            builder.Services.AddScoped<IGiveawayRepository, GiveawayRepository>();
            builder.Services.AddScoped<IItemRepository, ItemRepository>();
            builder.Services.AddScoped<IUserInventoryRepository, UserInventoryRepository>();
            builder.Services.AddScoped<IUserRepository, UserRepository>();
            builder.Services.AddScoped<ICsgoBackendService, CSGOBackendService>();
            builder.Services.AddScoped<ITotpProvider, TotpProvider>();
            builder.Services.AddScoped<IDateTimeProvider, DateTimeProvider>();
            builder.Services.AddScoped<IPasswordAuthenticationProvider, PasswordAuthenticationProvider>();
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
                    policy.WithMethods("GET", "POST", "DELETE", "PUT");
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
                    Description = "Adjon meg egy érvényes access token-t.",
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

                option.CustomSchemaIds(type => {
                    if (type.Namespace != null && type.Namespace.StartsWith("csgo"))
                    {
                        return type.Name;
                    }
                    else
                    {
                        return type.FullName;
                    }
                });

                option.SchemaFilter<ExcludeFido2NetLibSchemas>();
            });
            builder.Services.AddQuartz(q =>
            {
                var jobKey = new JobKey("GiveawayJob");

                q.AddJob<GiveawayJob>(opts => opts.WithIdentity(jobKey));

                q.AddTrigger(opts => opts
                    .ForJob(jobKey)
                    .WithIdentity("GiveawayJob-trigger")
                    .WithCronSchedule("0 0/1 * * * ?"));
            });
            builder.Services.AddQuartzHostedService(options =>
            {
                options.WaitForJobsToComplete = true;
            });
            builder.Services.AddControllersWithViews();
            builder.Services.AddFido2(options =>
            {
                options.ServerDomain = new Uri(Globals.Config.BackUrl).Host;
                options.ServerName = "CSGO";
                options.Origins = new HashSet<string>([Globals.Config.FrontUrl]);
                options.TimestampDriftTolerance = 300000;
            });

            var app = builder.Build();
            using (var serviceScope = app.Services.CreateScope())
            {
                var context = serviceScope.ServiceProvider.GetRequiredService<CsgoContext>();
                context.Database.EnsureCreated();
            }
            app.UseCors("API");
            app.UseSerilogRequestLogging();
            app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(uploadsPath),
                RequestPath = "/api/images",
                HttpsCompression = Microsoft.AspNetCore.Http.Features.HttpsCompressionMode.Compress,
                OnPrepareResponse = ctx =>
                {
                    var headers = ctx.Context.Response.GetTypedHeaders();
                    headers.CacheControl = new Microsoft.Net.Http.Headers.CacheControlHeaderValue
                    {
                        Public = true,
                        MaxAge = TimeSpan.FromHours(24)
                    };
                }
            });
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.ConfigObject.AdditionalItems.Add("persistAuthorization", "true");
            });
            app.MapControllers();
            app.UseSession();
            app.Run();
        }
    }
}
