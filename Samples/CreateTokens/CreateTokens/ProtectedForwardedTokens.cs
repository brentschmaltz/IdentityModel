//------------------------------------------------------------------------------
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreateTokens
{
    public class ProtectedForwardedTokens
    {
        private static Dictionary<string, string> _hashAlgorithmMap = new Dictionary<string, string> {
            { SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.Sha256 },
            { SecurityAlgorithms.EcdsaSha256Signature, SecurityAlgorithms.Sha256 },
            { SecurityAlgorithms.HmacSha256, SecurityAlgorithms.Sha256 },
            { SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256 },
            { SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256 },
            { SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256 },
            { SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.Sha384 },
            { SecurityAlgorithms.EcdsaSha384Signature, SecurityAlgorithms.Sha384 },
            { SecurityAlgorithms.HmacSha384, SecurityAlgorithms.Sha384 },
            { SecurityAlgorithms.HmacSha384Signature, SecurityAlgorithms.Sha384 },
            { SecurityAlgorithms.RsaSha384, SecurityAlgorithms.Sha384 },
            { SecurityAlgorithms.RsaSha384Signature, SecurityAlgorithms.Sha384 },
            { SecurityAlgorithms.EcdsaSha512, SecurityAlgorithms.Sha512 },
            { SecurityAlgorithms.EcdsaSha512Signature, SecurityAlgorithms.Sha512 },
            { SecurityAlgorithms.HmacSha512, SecurityAlgorithms.Sha512 },
            { SecurityAlgorithms.HmacSha512Signature, SecurityAlgorithms.Sha512 },
            { SecurityAlgorithms.RsaSha512, SecurityAlgorithms.Sha512 },
            { SecurityAlgorithms.RsaSha512Signature, SecurityAlgorithms.Sha512 }
        };

        public static void Run()
        {
            try
            {
                var signingCredentials = new SigningCredentials(KeyMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256);
                var protectedJwt = CreateProtectedForwardedToken(signingCredentials);
                var principal = ValidateProtectedForwardedToken(protectedJwt, signingCredentials);
                var protectedJwtFromJwt = CreateProtectedForwardedToken(protectedJwt, signingCredentials);
                var principalFromJwt = ValidateProtectedForwardedToken(protectedJwtFromJwt, signingCredentials);
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Exception thrown: '{ex}'.");
            }
        }

        private static string CreateProtectedForwardedToken(SigningCredentials signingCredentials)
        {
            var nonce = Guid.NewGuid().ToString();
            var jwtHeader = new JwtHeader(signingCredentials);
            var hashAlgorithm = GetHashAlgorithm(signingCredentials.Algorithm);
            jwtHeader[JwtRegisteredClaimNames.Nonce] = Base64UrlEncoder.Encode(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(nonce)));
            var jwtPayload = new JwtPayload(new List<Claim> { new Claim(JwtRegisteredClaimNames.Sub, "Subject"), new Claim(JwtRegisteredClaimNames.GivenName, "Bob") });
            var jwtToken = new JwtSecurityToken(jwtHeader, jwtPayload);
            var handler = new JwtSecurityTokenHandler();
            var protectedJwt = handler.WriteToken(jwtToken);
            jwtHeader[JwtRegisteredClaimNames.Nonce] = nonce;

            string[] tokenSegments = protectedJwt.Split('.');
            var encodedProtectedHeader = jwtHeader.Base64UrlEncode();
            protectedJwt = string.Join(".", 
                                       encodedProtectedHeader,
                                       tokenSegments[1],
                                       tokenSegments[2]);

            var protectedJwtToken = new JwtSecurityToken(protectedJwt);

            Console.WriteLine($"CreateProtectedForwardedToken: ProtectedJwtToken: '{protectedJwtToken}'.");

            return protectedJwt;
        }

        private static string CreateProtectedForwardedToken(string jwt, SigningCredentials signingCredentials)
        {
            string[] tokenSegments = jwt.Split('.');
            if (tokenSegments.Length != 3)
                throw new InvalidOperationException("jwt must be three parts.");

            JObject header = JObject.Parse(Base64UrlEncoder.Decode(tokenSegments[0]));

            var alg = header.Property(JwtHeaderParameterNames.Alg);
            if (alg == null)
                throw new InvalidOperationException("JwtHeader is missing 'alg'");

            var hashAlgorithm = GetHashAlgorithm(alg.Value.Value<string>());
            var nonce = Guid.NewGuid().ToString();
            var hashedEncodedNonce = Base64UrlEncoder.Encode(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(nonce)));

            var originalJwtHeader = JwtHeader.Base64UrlDeserialize(tokenSegments[0]);
            var protectedJwtHeader = new JwtHeader(signingCredentials);
            foreach (var kv in originalJwtHeader)
            {
                if (kv.Key == JwtHeaderParameterNames.Alg)
                    continue;

                if (kv.Key == JwtHeaderParameterNames.Kid)
                    continue;

                if (kv.Key == JwtHeaderParameterNames.X5c)
                    continue;

                protectedJwtHeader[kv.Key] = kv.Value;
            }

            protectedJwtHeader[JwtRegisteredClaimNames.Nonce] = hashedEncodedNonce;

            var jwtToken = new JwtSecurityToken(protectedJwtHeader, JwtPayload.Base64UrlDeserialize(tokenSegments[1]));
            var handler = new JwtSecurityTokenHandler();
            var protectedJwt = handler.WriteToken(jwtToken);

            protectedJwtHeader[JwtRegisteredClaimNames.Nonce] = nonce;

            tokenSegments = protectedJwt.Split('.');
            var encodedProtectedHeader = protectedJwtHeader.Base64UrlEncode();
            protectedJwt = string.Join(".",
                                       encodedProtectedHeader,
                                       tokenSegments[1],
                                       tokenSegments[2]);

            var protectedJwtToken = new JwtSecurityToken(protectedJwt);

            Console.WriteLine($"CreateProtectedForwardedToken (from jwt): ProtectedJwtToken: '{protectedJwtToken}'.");

            return protectedJwt;
        }

        private static HashAlgorithm GetHashAlgorithm(string signatureAlgorithm)
        {
            string hashAlgorithmName;
            if (!_hashAlgorithmMap.TryGetValue(signatureAlgorithm, out hashAlgorithmName))
                throw new InvalidOperationException("JwtHeader 'alg' does not map to any know hash algorithm");

            switch (hashAlgorithmName)
            {
                case SecurityAlgorithms.Sha256:
                    return SHA256.Create();

                case SecurityAlgorithms.Sha384:
                    return SHA384.Create();

                case SecurityAlgorithms.Sha512:
                    return SHA512.Create();

                default:
                    throw new InvalidProgramException($"hashAlgorithm unknown: '{hashAlgorithmName}', check _hashAlgorithmMap expect only Sha256, Sha384, Sha512");
            }
        }

        private static ClaimsPrincipal ValidateProtectedForwardedToken(string jwt, SigningCredentials signingCredentials)
        { 
            string[] tokenSegments = jwt.Split('.');
            if (tokenSegments.Length != 3)
                throw new InvalidOperationException("jwt must be three parts.");

            JObject header = JObject.Parse(Base64UrlEncoder.Decode(tokenSegments[0]));
            JProperty nonceProperty = header.Property(JwtRegisteredClaimNames.Nonce);
            if (nonceProperty == null)
                throw new InvalidOperationException("jwt must have a nonce.");

            var alg = header.Property(JwtHeaderParameterNames.Alg);
            if (alg == null)
                throw new InvalidOperationException("JwtHeader is missing 'alg'");

            var hashAlgorithm = GetHashAlgorithm(alg.Value.Value<string>());
            nonceProperty.Value = Base64UrlEncoder.Encode(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(nonceProperty.Value.Value<string>())));

            var protectedToken = string.Join(
                    ".",
                    Base64UrlEncoder.Encode(header.ToString(Formatting.None)),
                    tokenSegments[1],
                    tokenSegments[2]);

            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = signingCredentials.Key,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuer = false
            };

            SecurityToken validatedToken;
            Console.WriteLine($"ValidateUsingJson: original token: '{new JwtSecurityToken(jwt)}'");

            try
            {
                var principal = (new JwtSecurityTokenHandler()).ValidateToken(protectedToken, validationParameters, out validatedToken);
                Console.WriteLine($"ValidateUsingJson: validated token: '{validatedToken as JwtSecurityToken}'.");
                return principal;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ValidateUsingJson: threw on validation: '{ex}'.");
            }

            return null;
        }
    }
}
