using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace SendResponse
{
    class Program
    {
        static void Main(string[] args)
        {
            PostAsync().Wait();
        }


        static async Task PostAsync()
        {
            var audience = "microsoft.com";
            var issuer = "contoso.com";
            var tokenHandler = new JwtSecurityTokenHandler();

            var symmetricSecurityKey = new SymmetricSecurityKey(Convert.FromBase64String("VbbbbmlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE="));
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = symmetricSecurityKey,
                ValidAudience = audience,
                ValidIssuer = issuer,
            };

            var subject = new ClaimsIdentity(
                new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Aud, audience),
                    new Claim(JwtRegisteredClaimNames.Email, "bob@contoso.com"),
                    new Claim(JwtRegisteredClaimNames.GivenName, "bob"),
                    new Claim(JwtRegisteredClaimNames.Sub, "123456789")
                });

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Issuer = "contoso.com",
                SigningCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256),
                Subject = subject
            };

            var message = new OpenIdConnectMessage()
            {
                IdToken = tokenHandler.CreateEncodedJwt(tokenDescriptor)
            };

            //&state = ol74jG % 2BwWWOvg2t0 & session_state = 0f159484 - a764 - 4723 - 9004 - eff333944185

            var data = JsonConvert.SerializeObject(message, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
            var httpClient = new HttpClient();
            var stringContent = new StringContent(data);

            var response = await httpClient.PostAsync(@"http://localhost:3000/auth/openid/return", stringContent);
            response.EnsureSuccessStatusCode();
            var retval = await response.Content.ReadAsStreamAsync();

            Console.WriteLine("return: '{0}'", response);

            return;
        }
    }
}
