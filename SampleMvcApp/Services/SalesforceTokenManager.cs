using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Net.Http;
using Newtonsoft.Json;
using System.Diagnostics;

namespace SampleMvcApp.Services
{
    public class SalesforceTokenManager
    {
        //"https://test.salesforce.com/services/oauth2/token"
        public static async Task<AccessToken> getAccessToken(string url, string clientId, String secret, string username, string password)
        {
            var client = new HttpClient();
            var parameters = new Dictionary<string, string>();
            parameters["grant_type"] = "password";
            parameters["client_id"] = clientId;
            parameters["client_secret"] = secret;
            parameters["username"] = username;
            parameters["password"] = password;

            var result = await client.PostAsync(url, new FormUrlEncodedContent(parameters));
            var contents = await result.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<AccessToken>(contents);
        }

        public class AccessToken
        {
            public string access_token { get; set; }
            public string id { get; set; }
            public string instance_url { get; set; }
            public string scope { get; set; }
            public string token_type { get; set; }
        }
    }
}
