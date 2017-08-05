using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using Newtonsoft.Json;
using System.Diagnostics;

namespace SampleMvcApp.Services
{
    //call to send email /services/apexrest/api/v2/member/lodoss118+1982118@gmail.com/forgotpw?source=qcom
    //call to validate hash /services/apexrest/api/v2/member/lodoss118+1982118@gmail.com/forgotpw?source=qcom&token=523065fcab8aab6cddece99d062c540a

    public class SalesforceService
    {
        //code 10008 = email has been sent
        public static async Task<Response> SendEmail(string instanceUrl, string accessToken, string email)
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + accessToken);

            string url = instanceUrl + "/services/apexrest/api/v2/member/" + email + "/forgotpw?source=qcom";
            
            var result = await client.GetAsync(url);
            var contents = await result.Content.ReadAsStringAsync();

            Debug.WriteLine(contents);
            return JsonConvert.DeserializeObject<Response>(contents);
        }

        //code 10014 = hash matches
        public static async Task<Response> CheckHash(string instanceUrl, string accessToken, string email, string token)
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + accessToken);

            string url = instanceUrl + "/services/apexrest/api/v2/member/" + email + "/forgotpw?source=qcom&token=" + token;

            var result = await client.GetAsync(url);
            var contents = await result.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<Response>(contents);
        }

        public class Response
        {
            public Data responseAccount { get; set; }
            public string code { get; set; }
        }

        public class Data
        {
            public string code { get; set; }
        }
    }
}
