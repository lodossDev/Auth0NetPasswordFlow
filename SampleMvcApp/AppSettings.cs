using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SampleMvcApp
{
    public class AppSettings
    {
        public Auth0Settings Auth0 { get; set; }
        public SfdcSettings Sfdc { get; set; }
    }

    public class Auth0Settings
    {
        public string Domain { get; set; }

        public string CallbackUrl { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string Audience { get; set; }

        public Auth0Settings Api { get; set; }
    }

    public class SfdcSettings
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Url { get; set; }
    }
}
