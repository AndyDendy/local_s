using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Local_Server
{
    class Program
    {
        public static string local_ip = string.Empty;
        static void Main(string[] args)
        {

            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    local_ip = ip.ToString();
                    Console.WriteLine(ip.ToString());
                }
            }
            Console.WriteLine("Press any key to start initialization...");
            Console.ReadKey();
            Console.WriteLine("running...");
            string[] prefixes = new string[] { $"http://{local_ip}/", "http://localhost:8080/" };
            WebServer server = new WebServer(prefixes);
            server.Start();
            TCPServer tcpserver = new TCPServer(local_ip);
            tcpserver.Start();
            Console.ReadKey();
            server.Stop();

        }
    }
    public class TCPServer
    {
        private readonly TcpListener core;
        public TCPServer(string vr)
        {
            core = new TcpListener(IPAddress.Parse(vr), 500);
        }
        public void Start()
        {

            core.Start();
            ThreadPool.QueueUserWorkItem(zero =>
            {
                while (true)
                {
                    ThreadPool.QueueUserWorkItem(core_context =>
                    {
                        TcpClient context = core_context as TcpClient;

                        if (context != null)
                        {
                            Process(context);
                        }
                        else
                        {
                            return;
                        }
                    }, core.AcceptTcpClient());
                }
            });
        }
        void Process(TcpClient client)
        {
            bool done = false;
            string par = string.Empty;
            NetworkStream stream = client.GetStream();
            //handshake!!!!!!!!!!!!!!!!!!!!
            while (!done)
            {
                while (!stream.DataAvailable)
                {
                    Thread.Sleep(1000);
                }
                while (client.Available < 3)
                {
                    Thread.Sleep(1000);
                }

                byte[] bytes = new byte[client.Available];
                stream.Read(bytes, 0, client.Available);
                string s = Encoding.UTF8.GetString(bytes);
                if (Regex.IsMatch(s, "^GET", RegexOptions.IgnoreCase))
                {
                    Console.WriteLine("=====Handshaking from client=====\n{0}", s);
                    string swk = Regex.Match(s, "Sec-WebSocket-Key: (.*)").Groups[1].Value.Trim();
                    string swka = swk + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                    byte[] swkaSha1 = System.Security.Cryptography.SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(swka));
                    string swkaSha1Base64 = Convert.ToBase64String(swkaSha1);

                    byte[] response = Encoding.UTF8.GetBytes(
                        "HTTP/1.1 101 Switching Protocols\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Sec-WebSocket-Accept: " + swkaSha1Base64 +
                        "\r\n\r\n");
                    stream.Write(response, 0, response.Length);
                }
                else
                {

                    bool fin = (bytes[0] & 0b10000000) != 0,
                        mask = (bytes[1] & 0b10000000) != 0;

                    int opcode = bytes[0] & 0b00001111,
                        msglen = bytes[1] - 128,
                        offset = 2;

                    if (msglen == 126)
                    {
                        msglen = BitConverter.ToUInt16(new byte[] { bytes[3], bytes[2] }, 0);
                        offset = 4;
                    }
                    else if (msglen == 127)
                    {
                        Console.WriteLine("TODO: msglen == 127, needs qword to store msglen");
                    }

                    if (msglen == 0)
                        Console.WriteLine("msglen == 0");
                    else if (mask)
                    {
                        byte[] decoded = new byte[msglen];
                        byte[] masks = new byte[4] { bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3] };
                        offset += 4;

                        for (int i = 0; i < msglen; ++i)
                            decoded[i] = (byte)(bytes[offset + i] ^ masks[i % 4]);

                        string text = Encoding.UTF8.GetString(decoded);
                        Console.WriteLine("{0}", text);
                        par = text;
                    }
                    else
                        Console.WriteLine("mask bit not set");

                    Console.WriteLine();
                    done = true;
                }
            }
            //handshake!!!!!!!!!!!!!!!!!!!!
            int f = 0;
            while (done)
            {
                f++;
                Thread.Sleep(2000);
                List<byte> lb = new List<byte>();
                lb.Add(0x81);
                lb.Add(0x05);
                lb.AddRange(Encoding.UTF8.GetBytes("11111"));
                stream.Write(lb.ToArray(), 0, 7);
            }
        }
    }
    public class WebServer
    {
        private readonly HttpListener core = new HttpListener();

        DataTable users, pages, projects, teams, teamprojects;
        public WebServer(params string[] pref)
        {

            LoadData(ref pages, "pages.xml");
            LoadData(ref users, "users.xml");
            LoadData(ref projects, "projects.xml");
            LoadData(ref teams, "teams.xml");
            LoadData(ref teamprojects, "teamprojects.xml");

            core.IgnoreWriteExceptions = true;
            foreach (string s in pref)
            {
                core.Prefixes.Add(s);
            }
        }
        public void LoadData(ref DataTable dt, string name)
        {
            DataSet dataSet = new DataSet();
            FileStream stream = new FileStream(name, FileMode.Open);
            dataSet.ReadXml(stream, XmlReadMode.InferTypedSchema);
            stream.Close();
            dt = dataSet.Tables[0];
        }
        public void Start()
        {
            core.Start();
            ThreadPool.QueueUserWorkItem(zero =>
            {
                while (core.IsListening)
                {
                    ThreadPool.QueueUserWorkItem(core_context =>
                    {

                        HttpListenerContext context = core_context as HttpListenerContext;

                        if (context == null)
                        {
                            return;
                        }
                        else
                        {
                            Console.WriteLine(context.Request.Url);
                            LoadPage(ref context);
                            context.Response.OutputStream.Close();
                        }

                    }, core.GetContext());
                }
            });
        }
        public void ChangeValue(ref DataTable dt, int index1, int index2, string word, string new_value)
        {
            int len = dt.Rows.Count;
            for (int i = 0; i < len; i++)
            {
                string ind_val = dt.Rows[i].ItemArray[index1].ToString();
                if (ind_val.Equals(word))
                {
                    dt.Rows[i][index2] = new_value;
                    break;
                }
            }
        }
        public string GetProject(DataTable dt, string w1, string w2, int i1, int i2, int i3)
        {
            string res = string.Empty;
            int len = dt.Rows.Count;
            for (int i = 0; i < len; i++)
            {
                string val1 = dt.Rows[i].ItemArray[i1].ToString(), val2 = dt.Rows[i].ItemArray[i2].ToString();
                if (val1 == w1 && val2 == w2)
                {
                    res = dt.Rows[i].ItemArray[i3].ToString();
                    break;
                }
            }
            return res;
        }
        public void UpdateProject(DataTable dt, string w1, string w2, string w3, int i1, int i2, int i3)
        {
            int len = dt.Rows.Count;
            for (int i = 0; i < len; i++)
            {
                string val1 = dt.Rows[i].ItemArray[i1].ToString(), val2 = dt.Rows[i].ItemArray[i2].ToString();
                if (val1 == w1 && val2 == w2)
                {
                    dt.Rows[i][i3] = w3;
                    break;
                }
            }
        }
        public string CreateTeamList(DataTable dt, string team)
        {
            string result = string.Empty;
            int len = dt.Rows.Count;
            for (int i = 0; i < len; i++)
            {
                string val1 = dt.Rows[i].ItemArray[0].ToString(), val2 = dt.Rows[i].ItemArray[2].ToString();
                if (val1 == team)
                {
                    result += $"<button type=\"button\" onclick=\"LoadWork(\'{val1}\',\'{val2}\')\">{val2}</button>";
                }
            }
            if (string.IsNullOrEmpty(result))
            {
                result = "<p>your repository is empty</p>";
            }
            return result;
        }
        public string CreateList(DataTable dt, string word)
        {
            string result = string.Empty;
            int len = dt.Rows.Count;
            for (int i = 0; i < len; i++)
            {
                string ind_val = dt.Rows[i].ItemArray[0].ToString();
                if (ind_val.Equals(word))
                {
                    string imp = dt.Rows[i].ItemArray[2].ToString();
                    result += $"<button type=\"button\" onclick=\"LoadWork(\'\',\'{imp}\')\">{imp}</button>";
                }
            }
            if (string.IsNullOrEmpty(result))
            {
                result = "<p>your repository is empty</p>";
            }
            return result;
        }
        public string LoadTeams(DataTable dt, string word)
        {
            string result = string.Empty;
            int len = dt.Rows.Count;
            for (int i = 0; i < len; i++)
            {
                string[] ind_val = dt.Rows[i].ItemArray[0].ToString().Split(';');
                if (ind_val.Contains(word))
                {
                    string team = dt.Rows[i].ItemArray[1].ToString();
                    result += $"<button type=\"button\" onclick=\"LoadList(\'{team}\')\">{team}</button>";
                }
            }
            result += "<button type=\"button\" onclick=\"LoadList(\'\')\">Solo projects</button>";
            return result;
        }
        public string[] UniversalF(DataTable dt, int[] authinds, string[] authwords, int[] exportinds)
        {
            bool ok = true;
            int len = dt.Rows.Count, reql = authinds.Length, respl = exportinds.Length;
            string[] values = new string[reql];
            string[] value = new string[respl];
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < reql; j++)
                {
                    values[j] = dt.Rows[i].ItemArray[authinds[j]].ToString();
                }
                for (int j = 0; j < reql; j++)
                {
                    if (authwords[j] != values[j])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                {
                    for (int j = 0; j < respl; j++)
                    {
                        value[j] = dt.Rows[i].ItemArray[exportinds[j]].ToString();
                    }

                    return value;
                }
                ok = true;
            }
            return value;
        }
        public void UniversalM(ref DataTable dt, int[] authinds, string[] authwords, int[] importinds, string[] importwords)
        {
            bool ok = true;
            int len = dt.Rows.Count, reql = authinds.Length, respl = importinds.Length;
            string[] values = new string[reql];
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < reql; j++)
                {
                    values[j] = dt.Rows[i].ItemArray[authinds[j]].ToString();
                }
                for (int j = 0; j < reql; j++)
                {
                    if (authwords[j] != values[j])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                {
                    for (int j = 0; j < respl; j++)
                    {
                        dt.Rows[i][importinds[j]] = importwords[j];
                    }
                }
                ok = true;
            }
        }
        public string FindValue(DataTable dt, int index1, int index2, string word)
        {
            string value = null;
            int len = dt.Rows.Count;
            for (int i = 0; i < len; i++)
            {
                string ind_val = dt.Rows[i].ItemArray[index1].ToString();
                if (ind_val.Equals(word))
                {
                    value = dt.Rows[i].ItemArray[index2].ToString();
                    break;
                }
            }
            return value;
        }
        public bool Access(CookieCollection cl)
        {
            try
            {
                Cookie cookie = cl[0];
                string[] arr = cookie.Value.Replace("id=", "").Split('!');
                ;
                if (arr[1] == UniversalF(users, new int[] { 0 }, new string[] { arr[0] }, new int[] { 2 })[0])
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
        public void LoadPage(ref HttpListenerContext context)
        {
            try
            {
                string url = context.Request.Url.ToString().Replace("http://localhost:8080/", "").Replace($"http://{Program.local_ip}/", ""), response = string.Empty, ext = Path.GetExtension(url), pars = string.Empty;
                if (url.Contains("?"))
                {
                    string[] arr = url.Split('?');
                    url = arr[0];
                    pars = arr[1];
                }
                byte[] buf = new byte[0];
                Stream stream = context.Request.InputStream;
                StreamReader reader = new StreamReader(stream);
                string request = reader.ReadToEnd();
                reader.Close();
                if (string.IsNullOrEmpty(ext))
                {
                    switch (url)
                    {
                        case "":
                            response = FindValue(pages, 0, 1, url);
                            break;
                        case "log_in":
                            {
                                string[] meta = request.Split('!');
                                string par = FindValue(users, 0, 1, meta[0]);
                                if (par == meta[1])
                                {
                                    Random rnd = new Random();
                                    int code = rnd.Next(-10000000, 10000001);
                                    context.Response.SetCookie(new Cookie("id", $"{meta[0]}!{code}"));
                                    response = $"http://{Program.local_ip}/admin";
                                    //ChangeValue(ref users, 0, 2, meta[0], code.ToString());
                                    UniversalM(ref users, new int[] { 0 }, new string[] { meta[0] }, new int[] { 2 }, new string[] { code.ToString() });
                                }
                            }
                            break;
                        case "sign_up":
                            {
                                string[] meta = request.Split('!');
                                string par = FindValue(users, 0, 0, meta[0]);
                                if (par == meta[0])
                                {

                                }
                                else
                                {
                                    Random rnd = new Random();
                                    int code = rnd.Next(-10000000, 10000001);
                                    context.Response.SetCookie(new Cookie("id", $"{meta[0]}!{code}"));
                                    response = $"http://{Program.local_ip}/admin";
                                    users.Rows.Add(meta[0], meta[1], code.ToString(), "");
                                }
                            }
                            break;
                        default:
                            if (Access(context.Request.Cookies))
                            {
                                Cookie cookie = context.Request.Cookies[0];
                                string[] arr = cookie.Value.Replace("id=", "").Split('!');
                                switch (url)
                                {
                                    case "teams":
                                        {
                                            response = LoadTeams(teams, arr[0]);
                                            break;
                                        }
                                    case "worksheets":

                                        {
                                            string team = pars.Replace("team=", "");
                                            if (!string.IsNullOrEmpty(team))
                                            {
                                                response = CreateTeamList(teamprojects, team);
                                                if (string.IsNullOrEmpty(response))
                                                {
                                                    context.Response.StatusCode = 404;
                                                }
                                            }
                                            else
                                            {
                                                response = CreateList(projects, arr[0]);
                                                if (string.IsNullOrEmpty(response))
                                                {
                                                    context.Response.StatusCode = 404;
                                                }
                                            }
                                            break;
                                        }
                                    case "workarea":
                                        {
                                            string[] data = pars.Split('&');
                                            if (!string.IsNullOrEmpty(data[0].Replace("team=", "")))
                                            {
                                                response = UniversalF(teamprojects, new int[] { 0, 2 }, new string[] { data[0].Replace("team=", ""), data[1].Replace("proj=", "") }, new int[] { 3 })[0];
                                                if (string.IsNullOrEmpty(response))
                                                {
                                                    context.Response.StatusCode = 404;
                                                }
                                            }
                                            else
                                            {
                                                response = UniversalF(projects, new int[] { 0, 2 }, new string[] { arr[0], data[1].Replace("proj=", "") }, new int[] { 3 })[0];
                                                if (string.IsNullOrEmpty(response))
                                                {
                                                    context.Response.StatusCode = 404;
                                                }
                                            }
                                            break;
                                        }
                                    case "update":
                                        {
                                            string team = pars.Replace("team=", "");
                                            if (string.IsNullOrEmpty(team))
                                            {
                                                int find = request.IndexOf("!");
                                                string projectname = request.Substring(0, find), source = request.Substring(find + 1);
                                                UniversalM(ref projects, new int[] { 0, 2 }, new string[] { arr[0], projectname }, new int[] { 3 }, new string[] { source });
                                            }
                                            else
                                            {
                                                int find = request.IndexOf("!");
                                                string projectname = request.Substring(0, find), source = request.Substring(find + 1);
                                                UniversalM(ref teamprojects, new int[] { 0, 2 }, new string[] { team, projectname }, new int[] { 3 }, new string[] { source });
                                            }
                                            break;
                                        }
                                    case "submit":
                                        {
                                            int find = request.IndexOf("!");
                                            string projectname = request.Substring(0, find), lang = request.Substring(find + 1);
                                            projects.Rows.Add(arr[0], lang, projectname, string.Empty);
                                            break;
                                        }
                                    default:
                                        response = UniversalF(pages, new int[] { 0 }, new string[] { url }, new int[] { 1 })[0];
                                        break;
                                }

                            }
                            else
                            {
                                context.Response.StatusCode = 403;
                            }
                            break;
                    }
                    buf = Encoding.UTF8.GetBytes(response);
                }
                else
                {

                    MemoryStream mem = new MemoryStream();
                    switch (ext)
                    {
                        case ".jpg":
                            context.Response.ContentType = "image/jpeg";
                            Image.FromFile(url).Save(mem, ImageFormat.Jpeg);
                            buf = mem.ToArray();
                            break;
                        case ".png":
                            break;
                        case ".ico":
                            break;
                        case ".js":
                            response = FindValue(pages, 0, 1, url);
                            context.Response.ContentType = "application/javascript";
                            buf = Encoding.UTF8.GetBytes(response);
                            break;
                        case ".css":
                            response = FindValue(pages, 0, 1, url);
                            context.Response.ContentType = "text/css";
                            buf = Encoding.UTF8.GetBytes(response);
                            break;
                        default:
                            context.Response.StatusCode = 404;
                            break;
                    }
                }
                context.Response.ContentLength64 = buf.Length;
                context.Response.OutputStream.Write(buf, 0, buf.Length);
            }
            catch
            {
                context.Response.StatusCode = 404;
            }
        }
        public void Stop()
        {
            users.WriteXml("users.xml");
            projects.WriteXml("project.xml");
            core.Abort();
            core.Close();
            core.Stop();
        }
    }
}
