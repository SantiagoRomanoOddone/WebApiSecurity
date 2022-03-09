using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WebApiSecurity.Services;

namespace WebApiSecurity.Controllers
{
    //[Route("api/[controller]")]
    [Route("v1/minipompom/jwt/creation")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }
        [AllowAnonymous]
        [HttpPost(nameof(Auth))]
        public IActionResult Auth([FromBody] LoginModel data)
        {
            var inputBody = new InputBody
            {
                method = HttpContext.Request.Method,
                channel = "sucursal",
                path = HttpContext.Request.Path
            };
            bool isValid = _userService.IsValidUserInformation(data);
            if (isValid)
            {
                var tokenString = GenerateJwtToken(data.UserName, inputBody);
                return Ok(new { Token = tokenString, Message = "Success" });
            }
            return BadRequest("Please pass the valid Username and Password");
        }

        [Authorize(AuthenticationSchemes = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet(nameof(GetResult))]
        public IActionResult GetResult()
        {
            return Ok("API Validated");
        }

        private string GenerateJwtToken(string userName, InputBody inputBody)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:key"]);

            var claims = new ClaimsIdentity(new[]
            {
                new Claim("id", userName),
                new Claim("input-body", JsonConvert.SerializeObject(inputBody))
            });

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                //TODO: Cambiar a 1min una vez finalizada la capacitación para cumplir con los requerimentos del trabajo
                Expires = DateTime.UtcNow.AddHours(4),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        #region A borrar
        //private string GenerateJwtToken(string userName)
        //{
        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var key = Encoding.ASCII.GetBytes(_configuration["Jwt:key"]);
        //    //TODO: How to describe the Token Claims properly

        //    var tokenDescriptor = new SecurityTokenDescriptor
        //    {
        //        Subject = new ClaimsIdentity(new[] 
        //        { 
        //            new Claim("id", userName),                  
        //        }),

        //        Expires = DateTime.UtcNow.AddMinutes(20),
        //        Issuer = _configuration["Jwt:Issuer"],
        //        Audience = _configuration["Jwt:Audience"],
        //        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        //    };
        //    var token = tokenHandler.CreateToken(tokenDescriptor);
        //    return tokenHandler.WriteToken(token);
        //}    
        #endregion
    }
    #region JsonProperties  
    /// <summary>  
    /// Json Properties  
    /// </summary>  
    public class LoginModel
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
    #endregion

}
