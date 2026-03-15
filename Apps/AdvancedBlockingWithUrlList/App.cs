/*
 AdvancedBlockingWithUrlList
 Supports:
  - ipListMaps (URL -> name)
  - group name auto-linked to ipListMaps name
  - TWO separate timers:
    1) Download timer: checks URL lists for changes every blockListUrlUpdateIntervalMinutes (default 5)
       with sleep of blockListUrlUpdateSleepSeconds (default 30) between each list download
    2) Resolve timer: re-resolves FQDN hostnames every ipListResolveIntervalSeconds (min 300 = 5min)
  - Resolve: batches of max 10 parallel, wait for batch to finish, then next batch
  - Resolve: IPv4 only (A records) — NO AAAA queries
  - IP addresses in lists are NOT resolved — only FQDN hostnames
  - Cache stored in {ApplicationFolder}/lists/
*/

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace AdvancedBlockingWithUrlList
{
    public sealed class App : IDnsApplication, IDisposable
    {
        IDnsServer? _dnsServer;

        bool _enableBlocking = true;
        uint _blockingAnswerTtl = 30;

        Dictionary<string, Group>? _groups;
        Dictionary<Uri, IpList> _allIpListZones = new Dictionary<Uri, IpList>(UriComparer.Instance);
        Dictionary<string, Uri> _nameToUrlMap = new Dictionary<string, Uri>(StringComparer.OrdinalIgnoreCase);

        Timer? _downloadTimer;
        Timer? _resolveTimer;

        int _downloadIntervalMinutes = 5;
        int _downloadSleepSeconds = 30;
        int _resolveIntervalSeconds = 300;
        int _httpTimeoutSeconds = 30;
        IPAddress[]? _globalResolveDnsServers;

        public void Dispose()
        {
            _downloadTimer?.Dispose();
            _downloadTimer = null;
            _resolveTimer?.Dispose();
            _resolveTimer = null;
        }

        public string Description => "AdvancedBlockingWithUrlList: URL-based IP lists with separate download/resolve timers, batch resolve max 10, IPv4 only.\n";

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            _downloadTimer?.Dispose();
            _downloadTimer = null;
            _resolveTimer?.Dispose();
            _resolveTimer = null;
            _allIpListZones = new Dictionary<Uri, IpList>(UriComparer.Instance);
            _nameToUrlMap = new Dictionary<string, Uri>(StringComparer.OrdinalIgnoreCase);
            _groups = null;

            JsonDocument doc = JsonDocument.Parse(config);
            JsonElement root = doc.RootElement;

            _enableBlocking = root.GetPropertyValue("enableBlocking", true);
            _blockingAnswerTtl = root.GetPropertyValue("blockingAnswerTtl", 30u);

            _downloadIntervalMinutes = Math.Max(1, root.GetPropertyValue("blockListUrlUpdateIntervalMinutes", 5));
            _downloadSleepSeconds = Math.Max(0, root.GetPropertyValue("blockListUrlUpdateSleepSeconds", 30));
            _httpTimeoutSeconds = Math.Max(5, root.GetPropertyValue("httpTimeoutSeconds", 30));
            _resolveIntervalSeconds = Math.Max(300, root.GetPropertyValue("ipListResolveIntervalSeconds", 300));

            if (root.TryGetProperty("ipListResolveDnsServers", out JsonElement dnsServers) && dnsServers.ValueKind == JsonValueKind.Array)
            {
                var list = new List<IPAddress>();
                foreach (var j in dnsServers.EnumerateArray())
                {
                    if (IPAddress.TryParse(j.GetString(), out IPAddress? a))
                        list.Add(a);
                }
                _globalResolveDnsServers = list.Count > 0 ? list.ToArray() : null;
            }
            else
            {
                _globalResolveDnsServers = null;
            }

            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Initializing...");
            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: enableBlocking=" + _enableBlocking
                + " downloadMin=" + _downloadIntervalMinutes
                + " downloadSleepSec=" + _downloadSleepSeconds
                + " resolveSec=" + _resolveIntervalSeconds
                + " httpTimeoutSec=" + _httpTimeoutSeconds);

            // ipListMaps: URL -> name
            if (root.TryGetProperty("ipListMaps", out JsonElement mapsElem) && mapsElem.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty p in mapsElem.EnumerateObject())
                {
                    string urlText = p.Name;
                    string? name = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : null;
                    if (string.IsNullOrEmpty(name)) continue;
                    if (Uri.TryCreate(urlText, UriKind.Absolute, out Uri? u))
                    {
                        try
                        {
                            if (!_nameToUrlMap.ContainsKey(name))
                                _nameToUrlMap[name] = u;

                            if (!_allIpListZones.ContainsKey(u))
                            {
                                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Creating IpList URL=" + u.AbsoluteUri + " name=" + name);
                                var iplist = new IpList(_dnsServer, u, _httpTimeoutSeconds, _globalResolveDnsServers);
                                _allIpListZones[u] = iplist;

                                try
                                {
                                    await iplist.DownloadAndParseAsync();
                                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Parsed URL=" + u.AbsoluteUri + " directIPs=" + iplist.DirectIpCount + " hostnames=" + iplist.HostnameCount);

                                    await iplist.ResolveHostnamesAsync();
                                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Resolved URL=" + u.AbsoluteUri + " totalIPs=" + iplist.TotalIpCount);
                                }
                                catch (Exception ex)
                                {
                                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Failed initial load URL=" + u.AbsoluteUri + " => " + ex.Message);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Error creating IpList: " + ex.Message);
                        }
                    }
                }
            }

            // parse groups
            if (root.TryGetProperty("groups", out JsonElement groupsElement) && groupsElement.ValueKind == JsonValueKind.Array)
            {
                var groups = new Dictionary<string, Group>(StringComparer.OrdinalIgnoreCase);

                foreach (JsonElement ge in groupsElement.EnumerateArray())
                {
                    Group g = new Group(this, ge);
                    groups[g.Name] = g;

                    if (_nameToUrlMap.TryGetValue(g.Name, out Uri? mappedUrl))
                    {
                        if (_allIpListZones.TryGetValue(mappedUrl, out IpList? ipList))
                        {
                            g.AddIpListZone(mappedUrl, ipList);
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Group '" + g.Name + "' auto-linked to URL=" + mappedUrl.AbsoluteUri);
                        }
                    }

                    g.LoadListZones(_allIpListZones, _nameToUrlMap);
                }

                _groups = groups;
            }

            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Init complete. Groups=" + (_groups?.Count ?? 0) + " IpLists=" + _allIpListZones.Count);

            // TIMER 1: Download — check URLs for changes
            var downloadDue = TimeSpan.FromMinutes(_downloadIntervalMinutes);
            _downloadTimer = new Timer(async _ =>
            {
                try
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Download] Starting...");
                    await DownloadAllListsAsync();
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Download] Done.");
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Download] Error: " + ex.Message);
                }
            }, null, downloadDue, downloadDue);

            // TIMER 2: Resolve — re-nslookup FQDN hostnames (IPv4 only, batch 10)
            var resolveDue = TimeSpan.FromSeconds(_resolveIntervalSeconds);
            _resolveTimer = new Timer(async _ =>
            {
                try
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Resolve] Starting...");
                    await ResolveAllListsAsync();
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Resolve] Done.");
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Resolve] Error: " + ex.Message);
                }
            }, null, resolveDue, resolveDue);
        }

        async Task DownloadAllListsAsync()
        {
            int i = 0;
            foreach (var kv in _allIpListZones)
            {
                if (i > 0 && _downloadSleepSeconds > 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(_downloadSleepSeconds));
                }

                try
                {
                    bool changed = await kv.Value.DownloadAndParseAsync();
                    if (changed)
                    {
                        _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Download] Content changed, re-resolving: " + kv.Key.AbsoluteUri);
                        await kv.Value.ResolveHostnamesAsync();
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Download] Error: " + kv.Key.AbsoluteUri + " => " + ex.Message);
                }

                i++;
            }
        }

        async Task ResolveAllListsAsync()
        {
            foreach (var kv in _allIpListZones)
            {
                try
                {
                    await kv.Value.ResolveHostnamesAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Resolve] Error: " + kv.Key.AbsoluteUri + " => " + ex.Message);
                }
            }
        }

        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult(true);

            if (_groups is not null)
            {
                foreach (var kv in _groups)
                {
                    try
                    {
                        if (kv.Value.IsClientInIpLists(remoteEP.Address))
                        {
                            if (!kv.Value.EnableBlocking)
                                return Task.FromResult(true);
                            else
                                return Task.FromResult(false);
                        }
                    }
                    catch { }
                }
            }

            return Task.FromResult(true);
        }

        public Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram?>(null);

            if (_groups is not null)
            {
                foreach (var kv in _groups)
                {
                    var g = kv.Value;
                    if (!g.EnableBlocking) continue;

                    if (!g.IsClientInIpLists(remoteEP.Address))
                        continue;

                    DnsQuestionRecord q = request.Question[0];

                    if (g.IsZoneBlocked(q.Name))
                        return Task.FromResult<DnsDatagram?>(CreateBlockedResponse(request, q));

                    if (g.IsZoneBlockedByRegex(q.Name))
                        return Task.FromResult<DnsDatagram?>(CreateBlockedResponse(request, q));
                }
            }

            return Task.FromResult<DnsDatagram?>(null);
        }

        DnsDatagram CreateBlockedResponse(DnsDatagram request, DnsQuestionRecord q)
        {
            var soa = new DnsSOARecordData(_dnsServer!.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 3600, 600, 86400, _blockingAnswerTtl);
            var auth = new DnsResourceRecord[] { new DnsResourceRecord(q.Name, DnsResourceRecordType.SOA, q.Class, _blockingAnswerTtl, soa) };
            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NxDomain, request.Question, null, auth);
        }

        // ---------- Helper / nested types ----------

        class UriComparer : IEqualityComparer<Uri>
        {
            public static readonly UriComparer Instance = new UriComparer();
            public bool Equals(Uri? x, Uri? y) => StringComparer.OrdinalIgnoreCase.Equals(x?.AbsoluteUri, y?.AbsoluteUri);
            public int GetHashCode(Uri obj) => StringComparer.OrdinalIgnoreCase.GetHashCode(obj.AbsoluteUri);
        }

        class Group
        {
            readonly App _app;
            public string Name { get; }
            public bool EnableBlocking { get; }
            public bool BlockAsNxDomain { get; }
            public UrlEntry[] IpListUrls { get; }

            Dictionary<Uri, IpList> _ipListZones = new Dictionary<Uri, IpList>(UriComparer.Instance);
            HashSet<string> _blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<System.Text.RegularExpressions.Regex> _blockedRegex = new List<System.Text.RegularExpressions.Regex>();

            public Group(App app, JsonElement json)
            {
                _app = app;
                Name = json.GetProperty("name").GetString() ?? "default";
                EnableBlocking = json.GetPropertyValue("enableBlocking", true);
                BlockAsNxDomain = json.GetPropertyValue("blockAsNxDomain", false);

                if (json.TryGetProperty("ipListUrls", out JsonElement ipListUrls) && ipListUrls.ValueKind == JsonValueKind.Array)
                {
                    var entries = new List<UrlEntry>();
                    foreach (var el in ipListUrls.EnumerateArray())
                    {
                        if (el.ValueKind == JsonValueKind.String)
                            entries.Add(new UrlEntry(el.GetString()!));
                        else if (el.ValueKind == JsonValueKind.Object)
                            entries.Add(new UrlEntry(el));
                    }
                    IpListUrls = entries.ToArray();
                }
                else
                {
                    IpListUrls = Array.Empty<UrlEntry>();
                }

                if (json.TryGetProperty("blocked", out JsonElement blocked) && blocked.ValueKind == JsonValueKind.Array)
                {
                    foreach (var b in blocked.EnumerateArray())
                    {
                        string? s = b.GetString();
                        if (!string.IsNullOrEmpty(s))
                            _blocked.Add(s.ToLowerInvariant());
                    }
                }

                if (json.TryGetProperty("blockedRegex", out JsonElement blockedRegexEl) && blockedRegexEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var r in blockedRegexEl.EnumerateArray())
                    {
                        string? pattern = r.GetString();
                        if (!string.IsNullOrEmpty(pattern))
                        {
                            try
                            {
                                _blockedRegex.Add(new System.Text.RegularExpressions.Regex(pattern,
                                    System.Text.RegularExpressions.RegexOptions.IgnoreCase |
                                    System.Text.RegularExpressions.RegexOptions.Compiled |
                                    System.Text.RegularExpressions.RegexOptions.Singleline));
                            }
                            catch { }
                        }
                    }
                }
            }

            public void AddIpListZone(Uri url, IpList ipList)
            {
                if (!_ipListZones.ContainsKey(url))
                    _ipListZones[url] = ipList;
            }

            public void LoadListZones(Dictionary<Uri, IpList> allIpLists, Dictionary<string, Uri> nameToUrlMap)
            {
                foreach (var ue in IpListUrls)
                {
                    if (ue.IsName)
                    {
                        if (nameToUrlMap.TryGetValue(ue.Name!, out Uri? mappedUrl))
                        {
                            if (allIpLists.TryGetValue(mappedUrl, out IpList? ipList))
                                _ipListZones[mappedUrl] = ipList;
                        }
                    }
                    else if (ue.Uri is not null)
                    {
                        if (allIpLists.TryGetValue(ue.Uri, out IpList? ipList))
                            _ipListZones[ue.Uri] = ipList;
                    }
                }
            }

            public bool IsClientInIpLists(IPAddress ip)
            {
                foreach (var kv in _ipListZones)
                {
                    try
                    {
                        if (kv.Value.IsIpFound(ip))
                            return true;
                    }
                    catch { }
                }
                return false;
            }

            public bool IsZoneBlocked(string domain)
            {
                domain = domain.ToLowerInvariant().TrimEnd('.');
                return _blocked.Contains(domain);
            }

            public bool IsZoneBlockedByRegex(string domain)
            {
                if (_blockedRegex.Count == 0) return false;
                domain = domain.ToLowerInvariant().TrimEnd('.');
                foreach (var rx in _blockedRegex)
                {
                    try
                    {
                        if (rx.IsMatch(domain))
                            return true;
                    }
                    catch { }
                }
                return false;
            }
        }

        class UrlEntry
        {
            public Uri? Uri { get; }
            public string? Name { get; }
            public bool IsName => Name is not null;
            public int ResolveIntervalSeconds { get; }
            public IPAddress[]? ResolveDnsServers { get; }

            public UrlEntry(string raw)
            {
                if (System.Uri.TryCreate(raw, UriKind.Absolute, out Uri? u))
                { Uri = u; Name = null; }
                else
                { Name = raw; Uri = null; }
                ResolveIntervalSeconds = 0;
                ResolveDnsServers = null;
            }

            public UrlEntry(JsonElement el)
            {
                if (el.ValueKind == JsonValueKind.String)
                {
                    var s = el.GetString()!;
                    if (System.Uri.TryCreate(s, UriKind.Absolute, out Uri? u2))
                    { Uri = u2; Name = null; }
                    else
                    { Name = s; Uri = null; }
                    ResolveIntervalSeconds = 0;
                    ResolveDnsServers = null;
                }
                else
                {
                    string url = el.GetProperty("url").GetString()!;
                    Uri = System.Uri.TryCreate(url, UriKind.Absolute, out Uri? u3) ? u3 : null;
                    Name = null;
                    ResolveIntervalSeconds = el.GetPropertyValue("resolveIntervalSeconds", 0);
                    if (el.TryGetProperty("resolveDnsServers", out JsonElement dnsServers) && dnsServers.ValueKind == JsonValueKind.Array)
                    {
                        var list = new List<IPAddress>();
                        foreach (var j in dnsServers.EnumerateArray())
                        {
                            if (IPAddress.TryParse(j.GetString(), out IPAddress? a))
                                list.Add(a);
                        }
                        ResolveDnsServers = list.Count > 0 ? list.ToArray() : null;
                    }
                }
            }
        }

        // ---- ListBase: download + cache in {ApplicationFolder}/lists/ ----
        abstract class ListBase
        {
            protected readonly IDnsServer _dnsServer;
            protected readonly Uri _listUrl;
            protected readonly string _cachePath;
            protected readonly int _httpTimeoutSeconds;
            public DateTime LastModified { get; protected set; } = DateTime.MinValue;

            protected ListBase(IDnsServer dnsServer, Uri listUrl, int httpTimeoutSeconds)
            {
                _dnsServer = dnsServer;
                _listUrl = listUrl;
                _httpTimeoutSeconds = httpTimeoutSeconds;
                Directory.CreateDirectory(Path.Combine(_dnsServer.ApplicationFolder, "lists"));
                _cachePath = Path.Combine(_dnsServer.ApplicationFolder, "lists",
                    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(listUrl.AbsoluteUri))).ToLowerInvariant());
            }

            protected async Task<bool> DownloadListFileAsync()
            {
                try
                {
                    if (_listUrl.Scheme == "file")
                    {
                        string src = _listUrl.LocalPath;
                        if (!File.Exists(src))
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] File not found: " + src);
                            return false;
                        }
                        DateTime srcTime = File.GetLastWriteTimeUtc(src);
                        if (File.Exists(_cachePath) && File.GetLastWriteTimeUtc(_cachePath) >= srcTime)
                            return false;
                        File.Copy(src, _cachePath, true);
                        LastModified = File.GetLastWriteTimeUtc(_cachePath);
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] File changed, copied " + src);
                        return true;
                    }
                    else
                    {
                        using HttpClient http = new HttpClient();
                        http.Timeout = TimeSpan.FromSeconds(_httpTimeoutSeconds);

                        if (File.Exists(_cachePath) && LastModified > DateTime.MinValue)
                            http.DefaultRequestHeaders.IfModifiedSince = new DateTimeOffset(LastModified);

                        using var resp = await http.GetAsync(_listUrl);

                        if (resp.StatusCode == HttpStatusCode.NotModified)
                            return false;

                        if (!resp.IsSuccessStatusCode)
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] HTTP " + (int)resp.StatusCode + " for " + _listUrl.AbsoluteUri);
                            return false;
                        }

                        byte[] newContent = await resp.Content.ReadAsByteArrayAsync();

                        // byte-compare with cache to detect real changes
                        if (File.Exists(_cachePath))
                        {
                            byte[] oldContent = await File.ReadAllBytesAsync(_cachePath);
                            if (oldContent.Length == newContent.Length)
                            {
                                bool same = true;
                                for (int i = 0; i < oldContent.Length; i++)
                                {
                                    if (oldContent[i] != newContent[i]) { same = false; break; }
                                }
                                if (same) return false;
                            }
                        }

                        await File.WriteAllBytesAsync(_cachePath, newContent);
                        LastModified = DateTime.UtcNow;
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] Changed! " + newContent.Length + " bytes from " + _listUrl.AbsoluteUri);
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    try { _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] Failed: " + _listUrl + " => " + ex.Message); } catch { }
                    return false;
                }
            }

            protected IEnumerable<string> ReadListLines()
            {
                if (!File.Exists(_cachePath)) yield break;
                using var sr = new StreamReader(_cachePath);
                string? line;
                while ((line = sr.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.Length == 0) continue;
                    if (line.StartsWith("#") || line.StartsWith("!")) continue;
                    yield return line;
                }
            }
        }

        // ---- IpList: IPs go direct, FQDN hostnames get resolved (A only, batch 10) ----
        class IpList : ListBase
        {
            const int RESOLVE_BATCH_SIZE = 10;

            readonly IPAddress[]? _resolveDnsServers;

            HashSet<IPAddress> _directIps = new HashSet<IPAddress>();
            HashSet<string> _hostnames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<IPAddress> _resolvedIps = new HashSet<IPAddress>();
            readonly object _lock = new object();

            public int DirectIpCount { get { lock (_lock) return _directIps.Count; } }
            public int HostnameCount { get { lock (_lock) return _hostnames.Count; } }
            public int ResolvedIpCount { get { lock (_lock) return _resolvedIps.Count; } }
            public int TotalIpCount { get { lock (_lock) return _directIps.Count + _resolvedIps.Count; } }

            public IpList(IDnsServer dnsServer, Uri listUrl, int httpTimeoutSeconds, IPAddress[]? resolveDnsServers)
                : base(dnsServer, listUrl, httpTimeoutSeconds)
            {
                _resolveDnsServers = resolveDnsServers;
            }

            public async Task<bool> DownloadAndParseAsync()
            {
                bool changed = await DownloadListFileAsync();
                if (changed)
                {
                    ParseFile();
                    return true;
                }
                lock (_lock)
                {
                    if (_directIps.Count == 0 && _hostnames.Count == 0 && File.Exists(_cachePath))
                    {
                        // first run, cache exists but not yet parsed
                    }
                    else
                    {
                        return false;
                    }
                }
                ParseFile();
                return false;
            }

            void ParseFile()
            {
                var ips = new HashSet<IPAddress>();
                var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var line in ReadListLines())
                {
                    if (IPAddress.TryParse(line, out IPAddress? ip))
                    {
                        ips.Add(ip);
                    }
                    else
                    {
                        string host = line.Trim().TrimEnd('.');
                        if (host.Length > 0)
                            hosts.Add(host);
                    }
                }

                lock (_lock)
                {
                    _directIps = ips;
                    _hostnames = hosts;
                    _resolvedIps = new HashSet<IPAddress>();
                }

                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Parse] " + _listUrl.AbsoluteUri
                    + " => " + ips.Count + " direct IPs, " + hosts.Count + " hostnames (FQDN)");
            }

            // Resolve FQDN hostnames: A records ONLY (IPv4), batches of max 10
            public async Task ResolveHostnamesAsync()
            {
                string[] hosts;
                lock (_lock)
                {
                    hosts = new string[_hostnames.Count];
                    _hostnames.CopyTo(hosts);
                }

                if (hosts.Length == 0)
                {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] " + _listUrl.AbsoluteUri + " no hostnames.");
                    return;
                }

                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] " + _listUrl.AbsoluteUri
                    + " resolving " + hosts.Length + " hostnames in batches of " + RESOLVE_BATCH_SIZE + " (A/IPv4 only)...");

                var newResolved = new HashSet<IPAddress>();
                int batchNum = 0;

                // process in batches of RESOLVE_BATCH_SIZE
                for (int offset = 0; offset < hosts.Length; offset += RESOLVE_BATCH_SIZE)
                {
                    batchNum++;
                    int count = Math.Min(RESOLVE_BATCH_SIZE, hosts.Length - offset);
                    var batchTasks = new List<Task>(count);

                    for (int j = 0; j < count; j++)
                    {
                        string host = hosts[offset + j];
                        batchTasks.Add(ResolveOneHostAsync(host, newResolved));
                    }

                    // wait for entire batch to finish before starting next
                    try { await Task.WhenAll(batchTasks); } catch { }

                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] Batch " + batchNum
                        + " done (" + count + " hosts), resolved so far: " + newResolved.Count + " IPs");
                }

                // replace resolved IPs (fresh)
                lock (_lock)
                {
                    _resolvedIps = newResolved;
                }

                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] " + _listUrl.AbsoluteUri
                    + " complete. directIPs=" + DirectIpCount + " resolvedIPs=" + newResolved.Count
                    + " totalIPs=" + TotalIpCount);
            }

            // Resolve single hostname — A record ONLY (IPv4), no AAAA
            async Task ResolveOneHostAsync(string host, HashSet<IPAddress> results)
            {
                try
                {
                    if (_resolveDnsServers is not null && _resolveDnsServers.Length > 0)
                    {
                        DnsClient client = new DnsClient(_resolveDnsServers);
                        client.Proxy = _dnsServer.Proxy;
                        client.PreferIPv6 = false;

                        try
                        {
                            var aResp = await client.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN));
                            foreach (var a in DnsClient.ParseResponseA(aResp))
                            {
                                lock (results) results.Add(a);
                                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] " + host + " -> " + a);
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] A failed " + host + ": " + ex.Message);
                        }
                    }
                    else
                    {
                        try
                        {
                            var aResp = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), 5000);
                            foreach (var a in DnsClient.ParseResponseA(aResp))
                            {
                                lock (results) results.Add(a);
                                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] " + host + " -> " + a);
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] A failed " + host + ": " + ex.Message);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] Fail " + host + ": " + ex.Message);
                }
            }

            public bool IsIpFound(IPAddress ip)
            {
                lock (_lock)
                {
                    return _directIps.Contains(ip) || _resolvedIps.Contains(ip);
                }
            }
        }
    }

    static class JsonElementExtensions
    {
        public static bool GetPropertyValue(this JsonElement element, string propertyName, bool defaultValue)
        {
            if (element.TryGetProperty(propertyName, out JsonElement value) && (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
                return value.GetBoolean();
            return defaultValue;
        }

        public static int GetPropertyValue(this JsonElement element, string propertyName, int defaultValue)
        {
            if (element.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int intValue))
                return intValue;
            return defaultValue;
        }

        public static uint GetPropertyValue(this JsonElement element, string propertyName, uint defaultValue)
        {
            if (element.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.Number && value.TryGetUInt32(out uint uintValue))
                return uintValue;
            return defaultValue;
        }
    }
}
