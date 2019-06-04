using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ClientTLS
{
    class Program
    {

        static string DNS = "admin.mediagoom.com";
        //static string DNS = "localhost";
        static int PORT = 444;

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {

           Console.WriteLine("Server Validation {0}", sslPolicyErrors);

           if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
    
            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }

        static int Main(string[] args)
        {
            
            System.Console.WriteLine(args.Length);

            bool ok = false;
            string response = "";

           

                //WebRequestHandler handler = new WebRequestHandler();
                //X509Certificate2 certificate = GetMyX509Certificate();
                //handler.ClientCertificates.Add(certificate);

                SocketsHttpHandler handler = new SocketsHttpHandler();
                handler.SslOptions = new SslClientAuthenticationOptions
                {
                    //ApplicationProtocols = 

                    RemoteCertificateValidationCallback = ValidateServerCertificate
                     ,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                     ,
                    AllowRenegotiation = true
                     ,
                    TargetHost = DNS
                     ,
                    ApplicationProtocols = new System.Collections.Generic.List<SslApplicationProtocol>()

                };

                X509Certificate2 x509Certificate = new X509Certificate2("merged.pfx", "termoli");

                //handler.SslOptions.ApplicationProtocols.Add(SslApplicationProtocol.Http2);

                handler.SslOptions.ClientCertificates = new X509CertificateCollection();
                handler.SslOptions.ClientCertificates.Add(x509Certificate);

                handler.AllowAutoRedirect = true;
                handler.SslOptions.EncryptionPolicy = EncryptionPolicy.RequireEncryption;


                //specify to use TLS 1.2 as default connection
                //System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                //System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;


                //handler.Proxy = new WebProxy("http://localhost:8888");

                HttpClient httpClient = new HttpClient(handler);




                //httpClient.BaseAddress = new Uri("https://localhost:30478");
                httpClient.BaseAddress = new Uri($"https://{DNS}:{PORT}");
                httpClient.DefaultRequestHeaders.Accept.Clear();



                Task<string> res = httpClient.GetStringAsync("/");

                ok = res.Wait(20000);

                if(ok)
                    response = res.Result;
            

            if (ok)
                Console.WriteLine(response);
            else
            {
                Console.WriteLine("Failed!");
                return 5;
            }

            return 0;
        }
    }
}
