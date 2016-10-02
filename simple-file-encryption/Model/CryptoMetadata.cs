using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SimpleFileEncryption.Model
{
    [Serializable]
    public class CryptoMetadata
    {
        public string EncryptedAt { get; set; }

        public string OriginalFilename { get; set; }

        public string MachineName { get; set; }

        public string Author { get; set; }

        public string AuthorDomain { get; set; }

        public string IpAddress { get; set; }

        public CryptoMetadata(string originalFilename)
        {
            this.EncryptedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            this.OriginalFilename = originalFilename;
            this.MachineName = Environment.MachineName;
            this.Author = Environment.UserName;
            this.AuthorDomain = Environment.UserDomainName;
            this.IpAddress = GetLocalIPAddress();
        }

        public static string GetLocalIPAddress()
        {
            if (!NetworkInterface.GetIsNetworkAvailable())
            {
                return "Not connected to the internet";
            }

            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }

            return "Could not get IP address";
        }
    }
}
