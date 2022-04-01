using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using WebApiSecurity.Controllers;
using WebApiSecurity.Middleware;
using WebApiSecurity.Services;

namespace WebApiSecurity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();

            #region Swagger Configuration

            services.AddSwaggerGen(swagger =>
            {
                //This is to generate the Default UI of Swagger Documentation
                swagger.SwaggerDoc("v1", new OpenApiInfo 
                
                { 
                    Title = "WebApiSecurity", 
                    Version = "v1",
                    Description = "ASP.NET Core 5.0 Web API"
                });
                // To Enable authorization using Swagger (JWT)
                swagger.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 12345abcdef\"",
                });
                swagger.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                          new OpenApiSecurityScheme
                            {
                                Reference = new OpenApiReference
                                {
                                    Type = ReferenceType.SecurityScheme,
                                    Id = "Bearer"
                                }
                            },
                            new string[] {}
                    }
                });
            });
            #endregion

            #region Authentication
            services.AddAuthentication(option =>
            {
                option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

            }).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    //Validate the server. That generates the token
                    ValidateIssuer = true,
                    //Validate the recipient of the token is authorized to receive
                    ValidateAudience = true,
                    //Check if the token is not expired and the signing key of the issuer is valid
                    ValidateLifetime = false,
                    //Validate signature of the token
                    ValidateIssuerSigningKey = true,

                    //I have to specify the values for "Audience", "Issuer" and "Secret key" in this project inside the appsettings.json file.
                    ValidIssuer = Configuration["Jwt:Issuer"],
                    ValidAudience = Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"])) //Configuration["JwtToken:SecretKey"]
                };
            });

            #endregion

            services.AddTransient<IUserService, UserService>();

            #region Open Telemetry
            services.AddOpenTelemetryTracing(
            builder =>
            {
                builder
                .AddSource(nameof(AuthController))
                .AddHttpClientInstrumentation()
                    .SetResourceBuilder(ResourceBuilder
                        .CreateDefault()
                        .AddService(Assembly.GetEntryAssembly().GetName().Name))
                    .AddAspNetCoreInstrumentation(
                    options =>
                    {
                        options.Enrich = Enrich;
                        options.RecordException = true;
                    }
                    )
                    .AddOtlpExporter(options => options.Endpoint = new Uri("http://localhost:4317"));
            });
            #endregion
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseSwagger();
            
            app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "WebApiSecurity v1"));



            app.UseMiddleware<JWTMiddleware>();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
        private static void Enrich(Activity activity, string eventName, object obj)
        {
            if (obj is HttpRequest request)
            {
                var context = request.HttpContext;
                activity.AddTag("http.flavor", GetHttpFlavour(request.Protocol));
                activity.AddTag("http.scheme", request.Scheme);
                activity.AddTag("http.client_ip", context.Connection.RemoteIpAddress);
                activity.AddTag("http.request_content_length", request.ContentLength);
                activity.AddTag("http.request_content_type", request.ContentType);

                var user = context.User;
                if (user.Identity?.Name is not null)
                {
                    activity.AddTag("enduser.id", user.Identity.Name);
                    activity.AddTag(
                        "enduser.scope",
                        string.Join(',', user.Claims.Select(x => x.Value)));
                }
            }
            else if (obj is HttpResponse response)
            {
                activity.AddTag("http.response_content_length", response.ContentLength);
                activity.AddTag("http.response_content_type", response.ContentType);
            }
        }
        public static string GetHttpFlavour(string protocol)
        {
            if (HttpProtocol.IsHttp10(protocol))
            {
                return "1.0";
            }
            else if (HttpProtocol.IsHttp11(protocol))
            {
                return "1.1";
            }
            else if (HttpProtocol.IsHttp2(protocol))
            {
                return "2.0";
            }
            else if (HttpProtocol.IsHttp3(protocol))
            {
                return "3.0";
            }

            throw new InvalidOperationException($"Protocol {protocol} not recognised.");
        }
    }
}
