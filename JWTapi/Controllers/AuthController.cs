using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTapi.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        /*
         * The following method is used to create the web token
         * which will be used by other method/services
         */
        [HttpPost("token")]
        public IActionResult Token()
        {
            var header = Request.Headers["Authorization"];
            if (header.ToString().StartsWith("Basic"))
            {
                var credentionalValue = header.ToString().Substring("Basic ".Length).Trim();
                var userNameAndPasswrodEncryption = Encoding.UTF8.GetString(Convert.FromBase64String(credentionalValue));
                var userNameAndPasswrod = userNameAndPasswrodEncryption.Split(":");

                //check the database
                if (userNameAndPasswrod[0] == "Admin" && userNameAndPasswrod[1] == "pass")
                {
                    var claims = new[] { new Claim(ClaimTypes.Name, userNameAndPasswrod[0]) };
                    //Password should come from database or configuration file
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my_secure_token_passwrod"));
                    //Using HmacSha256 encryption to encrypt my password
                    var signInCredentionals = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
                    var token = new JwtSecurityToken
                        (
                        issuer: "https://yo.com",
                        audience: "https://yo.com",
                        expires: DateTime.UtcNow.AddMinutes(2),
                        //Claims are used to keep track of user information
                        claims: claims,
                        //SingingCredentials will contain the encrypted password
                        signingCredentials: signInCredentionals
                        );
                    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                    return Ok(tokenString);
                }
            }
            return BadRequest("Not authenticated");
        }
    }
}