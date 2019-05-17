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

        static X509CertificateCollection get_coll()
        {
            X509Certificate x509Certificate = new X509Certificate("merged.pfx", "termoli");
            X509CertificateCollection coll = new X509CertificateCollection();
            coll.Add(x509Certificate);

            return coll;
        }

        static SslClientAuthenticationOptions get_ssl_options()
        {
            SslClientAuthenticationOptions sslOptions =
            new SslClientAuthenticationOptions
                               {
                                    //ApplicationProtocols = 
                                    
                                    RemoteCertificateValidationCallback = ValidateServerCertificate
                                    , EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                                    , AllowRenegotiation = true
                                    , TargetHost = DNS
                                    , ApplicationProtocols = new System.Collections.Generic.List<SslApplicationProtocol>()

                               };

                               

                               sslOptions.ClientCertificates = get_coll();
                              

                               sslOptions.ApplicationProtocols.Add(SslApplicationProtocol.Http2);

                               

           return sslOptions;
        }

        

        async static Task<int> TLS()
        {
            //TcpClient client = new TcpClient(DNS, PORT);

            try
            {

                Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(DNS, PORT);

                System.Console.WriteLine("Connecting {0}", DNS);

                socket.NoDelay = true;
                NetworkStream nstream = new NetworkStream(socket, ownsSocket: true);

                SslStream stream = new SslStream(nstream, false, ValidateServerCertificate);

                System.Threading.CancellationToken cancellationToken = new System.Threading.CancellationToken();

                SslClientAuthenticationOptions sslOptions = get_ssl_options();

                //await stream.AuthenticateAsClientAsync(sslOptions, cancellationToken);

                await stream.AuthenticateAsClientAsync(DNS, get_coll(), System.Security.Authentication.SslProtocols.Tls12, false);

                string get = "GET / HTTP/1.1\r\nHost: fca-dme.westeurope.cloudapp.azure.com\r\nConnection: close\r\n\r\n";

                byte[] bget = System.Text.Encoding.UTF8.GetBytes(get);

                await stream.WriteAsync(bget, 0, bget.Length);

                await stream.FlushAsync();

                byte[] buffer = new byte[2048];

                StringBuilder messageData = new StringBuilder();
                int bytes = -1;
                do
                {
                    bytes = await stream.ReadAsync(buffer, 0, buffer.Length);

                    // Use Decoder class to convert from bytes to UTF8
                    // in case a character spans two buffers.
                    Decoder decoder = Encoding.UTF8.GetDecoder();
                    char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                    decoder.GetChars(buffer, 0, bytes, chars, 0);
                    messageData.Append(chars);
                    // Check for EOF.
                    if (messageData.ToString().IndexOf("<EOF>") != -1)
                    {
                        break;
                    }
                } while (bytes != 0);

                Console.WriteLine(messageData.ToString());

            }
            catch (Exception e)
            {
                System.Console.WriteLine(e.ToString());

                return 1;
            }
            

            return 0;
        }
        static int Main(string[] args)
        {
            
            System.Console.WriteLine(args.Length);

            bool ok = false;
            string response = "";

            if (0 < args.Length)
            {
                Task<int> t = TLS();
                ok = t.Wait(10000);

                /*
                System.Console.Read();

                t = TLS();
                ok = t.Wait(10000);
                */

            }
            else
            {

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

                X509Certificate x509Certificate = new X509Certificate("merged.pfx", "termoli");

                handler.SslOptions.ApplicationProtocols.Add(SslApplicationProtocol.Http2);

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
            }

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
