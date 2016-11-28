using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace Wilson5x
{
    public class JwtWithJsonSubClaims
    {
        public static void Run()
        {
            var handler = new JwtSecurityTokenHandler()
            {
                SetDefaultTimesOnTokenCreation = false
            };

            var claims = new List<Claim>
            {
                new Claim("GeneralInfo_A", "Xema"),
                new Claim("GeneralInfo_B", "Xemab"),
                new Claim("Number", "1234-5678-9012-3456"),
                new Claim("Farm", "{\"FarmNumber\":\"12332\", \"Adress\": \"Farmersville\", \"Animalspecies\": \"Equidaes\"}", JsonClaimValueTypes.Json),
                new Claim("Farm", "{\"FarmNumber\":\"42343\", \"Adress\": \"NewYork\", \"Animalspecies\": \"Cattle\"}", JsonClaimValueTypes.Json),
                new Claim("Farm", "{\"FarmNumber\":\"55555\", \"Adress\": \"colchose\", \"Animalspecies\": \"Pigs\"}", JsonClaimValueTypes.Json)
            };

            var jobj = new JObject();
            var jArray = new JArray();
            jArray.Add(NewFarm("12332", "Farmersville", "Equidaes"));
            jArray.Add(NewFarm("42343", "NewYork", "Cattle"));
            jArray.Add(NewFarm("55555", "colchose", "Pigs"));

            var payload = new JwtPayload();
            payload.Add("GeneralInfo_A", "Xema");
            payload.Add("GeneralInfo_B", "Xemab");
            payload.Add("Number", "1234-5678-9012-3456");
            payload.Add("Farm", jArray);
            var header = new JwtHeader();
            var jwtTokenFromPayloadHeader = new JwtSecurityToken(header, payload);
            var jwtFromPayloadHeader = handler.WriteToken(jwtTokenFromPayloadHeader);
            var jwtTokenHydratedFromPayloadHeader = new JwtSecurityToken(jwtFromPayloadHeader);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims)
            };

            var jwtFromClaims = handler.CreateEncodedJwt(tokenDescriptor);
            var jwtTokenFromClaims = new JwtSecurityToken(jwtFromClaims);

            tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(jwtTokenFromClaims.Claims)
            };

            var jwtFromJwtClaims = handler.CreateEncodedJwt(tokenDescriptor);
            var jwtTokenFromJwtClaims = new JwtSecurityToken(jwtFromJwtClaims);

        }

        private static JObject NewFarm(string farmNumber, string address, string species)
        {
            var farm = new JObject();
            farm.Add("FarmNumber", farmNumber);
            farm.Add("Adress", address);
            farm.Add("Animalspecies", species);

            return farm;
        }
    }
}
