//
// Copyright © Microsoft Corporation, All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ExtendingCryptoSupport
{
    public class InjectHostHeaderHttpMessageHandler : DelegatingHandler
    {
        public InjectHostHeaderHttpMessageHandler(Uri networkUri)
        {
            NetworkUri = networkUri ?? throw new ArgumentNullException(nameof(networkUri));
        }

        /// <summary>
        /// Gets the NetworkUri to use when calling keyvault
        /// </summary>
        public Uri NetworkUri { get; private set; }

        /// <summary>
        /// Adds the Host header to every request if the "KmsNetworkUrl" configuration setting is specified.
        /// </summary>
        /// <param name="request"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestUri = request.RequestUri;
            var authority = string.Empty;
            var targetUri = requestUri;

            authority = targetUri.Authority;
            targetUri = new Uri(NetworkUri, targetUri.PathAndQuery);

            request.Headers.Add("Host", authority);
            request.RequestUri = targetUri;

            return base.SendAsync(request, cancellationToken).ContinueWith<HttpResponseMessage>(response =>
            {
                return response.Result;
            });
        }
    }
}

