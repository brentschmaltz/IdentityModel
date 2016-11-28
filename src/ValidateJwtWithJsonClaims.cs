using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Wilson5x
{
    public class ValidateJwtWithJsonClaims
    {
        public static void Run()
        {
            var jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImlzRW5jcnlwdGVkIjoiRmFsc2UiLCJ4NXQiOiI1M0VENjE1NTUwNTlBRDg3QUE4MkNBNTYwRTQ4QkIxMkM1MzdGOUY1IiwidmVyIjoiMi4xIn0.eyJhdWQiOiJIZWxpeC5TZWN1cml0eS5VdGlsIiwiaWF0IjoiMTQ3MjA5NjU1Ny43NDM3NiIsIm5iZiI6IjE0NzIwOTY1NDQuNzU3NTkiLCJDbGFpbVNldHMiOlt7IkNsYWltcyI6eyJzZXJ2ZXJJZCI6IkhlbGl4LkNvbnRhaW5lcnMuRGV2Iiwic2VydmVyVmVyc2lvbiI6ImRldiIsImlzc1g1dCI6IjUzRUQ2MTU1NTA1OUFEODdBQTgyQ0E1NjBFNDhCQjEyQzUzN0Y5RjUifSwiUHJvdmlkZXIiOiJIZWxpeC5Db250YWluZXJzLkRldi52ZGV2IiwiU2NoZW1hIjoiSGVsaXguQ29udGFpbmVyIiwiVmVyc2lvbiI6IlYxIn1dLCJpc3MiOiJIZWxpeC5Db250YWluZXJzLkRldi52ZGV2IiwiZXhwIjoiMTQ3MjA5Nzc0NC43NTg1OSIsInNzaWQiOiJjNmJkNzY3ZjE4YWU0ZTQyOTliMmY4YjJmNzhmODU1NSJ9.W8ARsO3IKMO_CBl5fMkgTEkPmoZZvjaX46-mmVHqT5hQAbQVBmnc18B9VxsSS34YKVE2dBQwZHjhu2ROSOCKeuHOqHjjS_HuSdDLOdi7rJUdpKw1GE-lBqxzUPojAlUvLRlq7KjbwipXd7bJyMk7chVU9r548pmljDAlm7SOqmM-qcZ8X0sgQcDxxZoacJiL9xQpbJPi9CVHC_ms2LJhm6AFcCNTlRZNgAmMvoIBWfjXVsVC92HFgqd_qTpMvudTs216LIfslpJC0WiU4SFWKV2Bt5rGGVVqSe4vXb4W1Si58t8ORcepRnkZ1jkEuKf2VpHTEw0ylwX_BLqnnKdavQ";
            var jwtHandler = new JwtSecurityTokenHandler();
            var validationParamaters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                SignatureValidator = (token, validationParameters) =>
                {
                    return new JwtSecurityToken(token);
                }              
            };

            SecurityToken securityToken = null;
            var principal = jwtHandler.ValidateToken(jwt, validationParamaters, out securityToken);
        }
    }
}
