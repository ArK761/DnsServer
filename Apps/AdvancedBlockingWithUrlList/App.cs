/*
 AdvancedBlockingWithUrlList
 Supports:
  - ipListMaps (URL -> name)
  - group name matched to ipListMaps name -> group uses that URL's IP list
  - global refresh interval (minutes) via blockListUrlUpdateIntervalMinutes
  - global resolve interval (seconds) via ipListResolveIntervalSeconds
  - global resolve DNS servers via ipListResolveDnsServers
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

        // groups parsed from config
        Dictionary<string, Group>? _groups;

        // all IpList instances keyed by URL
        Dictionary<Uri, IpList> _allIpListZones = new Dictionary<Uri, IpList>(UriComparer.Instance);

        // map name->url (derived from ipListMaps where value is name)
        Dictionary<string, Uri> _nameToUrlMap = new Dictionary<string, Uri>(StringComparer.OrdinalIgnoreCase);

        Timer? _updateTimer;
        int _refreshIntervalMinutes = 1440; // default 1 day
        int _globalResolveIntervalSeconds = 3600;
        IPAddress[]? _globalResolveDnsServers;

        public void Dispose()
        {
            _updateTimer?.Dispose();
            _updateTimer = null;
        }

        public string Description => "AdvancedBlockingWithUrlList: URL-based IP lists with global refresh and resolve settings.\n";

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            // clear previous state (re-init on config save)
            _updateTimer?.Dispose();
            _updateTimer = null;
            _allIpListZones = new Dictionary<Uri, IpList>(UriComparer.Instance);
            _nameToUrlMap = new Dictionary<string, Uri>(StringComparer.OrdinalIgnoreCase);
            _groups = null;

            JsonDocument doc = JsonDocument.Parse(config);
            JsonElement root = doc.RootElement;

            _enableBlocking = root.GetPropertyValue("enableBlocking", true);
            _blockingAnswerTtl = root.GetPropertyValue("blockingAnswerTtl", 30u);

            _refreshIntervalMinutes = root.GetPropertyValue("blockListUrlUpdateIntervalMinutes", 1440);
            _globalResolveIntervalSeconds = root.GetPropertyValue("ipListResolveIntervalSeconds", 3600);

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
            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: enableBlocking=" + _enableBlocking + " refreshMinutes=" + _refreshIntervalMinutes + " resolveSeconds=" + _globalResolveIntervalSeconds);

            // ipListMaps: URL -> name (string)
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
                            // store name->url
                            if (!_nameToUrlMap.ContainsKey(name))
                                _nameToUrlMap[name] = u;

                            // create IpList instance for this url
                            if (!_allIpListZones.ContainsKey(u))
                            {
                                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Creating IpList for URL=" + u.AbsoluteUri + " name=" + name);
                                var iplist = new IpList(_dnsServer, u, _globalResolveIntervalSeconds, _globalResolveDnsServers);
                                _allIpListZones[u] = iplist;

                                // await initial load so list is ready before processing requests
                                try
                                {
                                    await iplist.LoadAsync();
                                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Loaded IpList URL=" + u.AbsoluteUri + " hostnames=" + iplist.HostnameCount + " ips=" + iplist.IpCount);
                                }
                                catch (Exception ex)
                                {
                                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Failed to load IpList URL=" + u.AbsoluteUri + " => " + ex.Message);
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

            // parse groups - match group name to ipListMaps name
            if (root.TryGetProperty("groups", out JsonElement groupsElement) && groupsElement.ValueKind == JsonValueKind.Array)
            {
                var groups = new Dictionary<string, Group>(StringComparer.OrdinalIgnoreCase);

                foreach (JsonElement ge in groupsElement.EnumerateArray())
                {
                    Group g = new Group(this, ge);
                    groups[g.Name] = g;

                    // Auto-link: if group name matches a name in ipListMaps, link the IpList to this group
                    if (_nameToUrlMap.TryGetValue(g.Name, out Uri? mappedUrl))
                    {
                        if (_allIpListZones.TryGetValue(mappedUrl, out IpList? ipList))
                        {
                            g.AddIpListZone(mappedUrl, ipList);
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Group '" + g.Name + "' linked to IpList URL=" + mappedUrl.AbsoluteUri);
                        }
                    }

                    // Also load any explicit ipListUrls from group config
                    g.LoadListZones(_allIpListZones, _nameToUrlMap, _globalResolveIntervalSeconds, _globalResolveDnsServers);
                }

                _groups = groups;
            }

            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Initialization complete. Groups=" + (_groups?.Count ?? 0) + " IpLists=" + _allIpListZones.Count);

            // schedule periodic updates
            var due = TimeSpan.FromMinutes(Math.Max(1, _refreshIntervalMinutes));
            _updateTimer = new Timer(async _ =>
            {
                try
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: Running periodic update...");
                    await UpdateAllAsync();
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: Periodic update complete.");
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: Update error: " + ex.Message);
                }
            }, null, due, due);
        }

        async Task UpdateAllAsync()
        {
            List<Task<bool>> tasks = new List<Task<bool>>();
            foreach (var kv in _allIpListZones)
                tasks.Add(kv.Value.UpdateAsync());
            if (tasks.Count > 0)
            {
                await Task.WhenAll(tasks);
            }
        }

        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult(true);

            // Determine group by client IP membership in ip lists
            if (_groups is not null)
            {
                foreach (var kv in _groups)
                {
                    try
                    {
                        if (kv.Value.IsClientInIpLists(remoteEP.Address))
                        {
                            // client is in this group's IP list
                            if (!kv.Value.EnableBlocking)
                                return Task.FromResult(true); // group has blocking disabled, allow
                            else
                                return Task.FromResult(false); // group has blocking enabled, block (go to ProcessRequestAsync)
                        }
                    }
                    catch { }
                }
            }

            // client not in any group's IP list -> allow
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

                    // check if client is in this group
                    if (!g.IsClientInIpLists(remoteEP.Address))
                        continue;

                    DnsQuestionRecord q = request.Question[0];

                    // check blocked domains list
                    if (g.IsZoneBlocked(q.Name, out _, out _))
                    {
                        return Task.FromResult<DnsDatagram?>(CreateBlockedResponse(request, q));
                    }

                    // check blocked regex
                    if (g.IsZoneBlockedByRegex(q.Name))
                    {
                        return Task.FromResult<DnsDatagram?>(CreateBlockedResponse(request, q));
                    }
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

        // --------------------
        // Helper / nested types
        // --------------------

        // compare Uri by absolute uri
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

            // ip list references
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
                        {
                            entries.Add(new UrlEntry(el.GetString()!));
                        }
                        else if (el.ValueKind == JsonValueKind.Object)
                        {
                            entries.Add(new UrlEntry(el));
                        }
                    }
                    IpListUrls = entries.ToArray();
                }
                else
                {
                    IpListUrls = Array.Empty<UrlEntry>();
                }

                // parse blocked domains
                if (json.TryGetProperty("blocked", out JsonElement blocked) && blocked.ValueKind == JsonValueKind.Array)
                {
                    foreach (var b in blocked.EnumerateArray())
                    {
                        string? s = b.GetString();
                        if (!string.IsNullOrEmpty(s))
                            _blocked.Add(s.ToLowerInvariant());
                    }
                }

                // parse blockedRegex
                if (json.TryGetProperty("blockedRegex", out JsonElement blockedRegexEl) && blockedRegexEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var r in blockedRegexEl.EnumerateArray())
                    {
                        string? pattern = r.GetString();
                        if (!string.IsNullOrEmpty(pattern))
                        {
                            try
                            {
                                _blockedRegex.Add(new System.Text.RegularExpressions.Regex(pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.Singleline));
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

            // load mapping from global allIpLists (ensure instances exist for each referenced URL)
            public void LoadListZones(
                Dictionary<Uri, IpList> allIpLists,
                Dictionary<string, Uri> nameToUrlMap,
                int globalResolveIntervalSeconds,
                IPAddress[]? globalResolveDnsServers)
            {
                foreach (var ue in IpListUrls)
                {
                    if (ue.IsName)
                    {
                        if (nameToUrlMap.TryGetValue(ue.Name!, out Uri? mappedUrl))
                        {
                            if (!allIpLists.TryGetValue(mappedUrl, out IpList? ipList))
                            {
                                ipList = new IpList(_app._dnsServer!, mappedUrl, globalResolveIntervalSeconds, globalResolveDnsServers);
                                allIpLists[mappedUrl] = ipList;
                                _ = ipList.LoadAsync();
                            }
                            _ipListZones[mappedUrl] = ipList;
                        }
                    }
                    else if (ue.Uri is not null)
                    {
                        var url = ue.Uri;
                        if (!allIpLists.TryGetValue(url, out IpList? ipList))
                        {
                            int resolveSec = ue.ResolveIntervalSeconds == 0 ? globalResolveIntervalSeconds : ue.ResolveIntervalSeconds;
                            IPAddress[]? dns = ue.ResolveDnsServers ?? globalResolveDnsServers;
                            ipList = new IpList(_app._dnsServer!, url, resolveSec, dns);
                            allIpLists[url] = ipList;
                            _ = ipList.LoadAsync();
                        }
                        _ipListZones[url] = ipList;
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

            public bool IsZoneBlocked(string domain, out string? blockedDomain, out string? blockedRegex)
            {
                domain = domain.ToLowerInvariant().TrimEnd('.');
                if (_blocked.Contains(domain))
                {
                    blockedDomain = domain;
                    blockedRegex = null;
                    return true;
                }
                blockedDomain = null; blockedRegex = null;
                return false;
            }

            public bool IsZoneBlockedByRegex(string domain)
            {
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

        // UrlEntry: supports string names, string URLs or object { url, resolveIntervalSeconds, resolveDnsServers }
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
                {
                    Uri = u;
                    Name = null;
                    ResolveIntervalSeconds = 0;
                    ResolveDnsServers = null;
                }
                else
                {
                    Name = raw;
                    Uri = null;
                    ResolveIntervalSeconds = 0;
                    ResolveDnsServers = null;
                }
            }

            public UrlEntry(JsonElement el)
            {
                if (el.ValueKind == JsonValueKind.String)
                {
                    var s = el.GetString()!;
                    if (System.Uri.TryCreate(s, UriKind.Absolute, out Uri? u2))
                    {
                        Uri = u2;
                        Name = null;
                    }
                    else
                    {
                        Name = s;
                        Uri = null;
                    }
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

        abstract class ListBase
        {
            protected readonly IDnsServer _dnsServer;
            protected readonly Uri _listUrl;
            protected readonly string _cachePath;
            public DateTime LastModified { get; protected set; } = DateTime.MinValue;

            protected ListBase(IDnsServer dnsServer, Uri listUrl)
            {
                _dnsServer = dnsServer;
                _listUrl = listUrl;
                Directory.CreateDirectory(Path.Combine(_dnsServer.ApplicationFolder, "lists"));
                _cachePath = Path.Combine(_dnsServer.ApplicationFolder, "lists", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(listUrl.AbsoluteUri))).ToLowerInvariant());
            }

            protected async Task<bool> DownloadListFileAsync()
            {
                try
                {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Downloading " + _listUrl.AbsoluteUri);

                    if (_listUrl.Scheme == "file")
                    {
                        string src = _listUrl.LocalPath;
                        if (!File.Exists(src))
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: File not found: " + src);
                            return false;
                        }
                        DateTime srcTime = File.GetLastWriteTimeUtc(src);
                        if (File.Exists(_cachePath) && File.GetLastWriteTimeUtc(_cachePath) >= srcTime)
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Cache up to date for " + _listUrl.AbsoluteUri);
                            return false;
                        }
                        File.Copy(src, _cachePath, true);
                        LastModified = File.GetLastWriteTimeUtc(_cachePath);
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Copied file " + src + " to cache.");
                        return true;
                    }
                    else
                    {
                        using HttpClient http = new HttpClient();
                        http.Timeout = TimeSpan.FromSeconds(30);
                        using var resp = await http.GetAsync(_listUrl);
                        if (!resp.IsSuccessStatusCode)
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: HTTP " + (int)resp.StatusCode + " for " + _listUrl.AbsoluteUri);
                            return false;
                        }
                        byte[] content = await resp.Content.ReadAsByteArrayAsync();
                        await File.WriteAllBytesAsync(_cachePath, content);
                        LastModified = DateTime.UtcNow;
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Downloaded " + content.Length + " bytes from " + _listUrl.AbsoluteUri + " -> cache=" + _cachePath);
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    try { _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Download failed: " + _listUrl + " => " + ex.ToString()); } catch { }
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

        class IpList : ListBase
        {
            readonly int _resolveIntervalSeconds;
            readonly IPAddress[]? _resolveDnsServers;
            DateTime _lastResolved = DateTime.MinValue;

            HashSet<IPAddress> _resolvedIps = new HashSet<IPAddress>();
            HashSet<string> _hostnames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            readonly object _lock = new object();

            public int HostnameCount { get { lock (_lock) { return _hostnames.Count; } } }
            public int IpCount { get { lock (_lock) { return _resolvedIps.Count; } } }

            public IpList(IDnsServer dnsServer, Uri listUrl, int resolveIntervalSeconds = 3600, IPAddress[]? resolveDnsServers = null)
                : base(dnsServer, listUrl)
            {
                _resolveIntervalSeconds = resolveIntervalSeconds;
                _resolveDnsServers = resolveDnsServers;
            }

            public async Task LoadAsync()
            {
                await DownloadListFileAsync();
                LoadFromFile();
                await ResolveHostnamesAsync();
            }

            void LoadFromFile()
            {
                var ips = new HashSet<IPAddress>();
                var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var line in ReadListLines())
                {
                    if (IPAddress.TryParse(line, out IPAddress? ip))
                    {
                        ips.Add(ip);
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [" + _listUrl.AbsoluteUri + "] Loaded IP: " + ip);
                    }
                    else
                    {
                        string host = line.Trim().TrimEnd('.');
                        if (host.Length > 0)
                        {
                            hosts.Add(host);
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [" + _listUrl.AbsoluteUri + "] Loaded hostname: " + host);
                        }
                    }
                }

                lock (_lock)
                {
                    _resolvedIps = ips;
                    _hostnames = hosts;
                }

                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [" + _listUrl.AbsoluteUri + "] Parsed: " + ips.Count + " IPs, " + hosts.Count + " hostnames");
            }

            public async Task<bool> UpdateAsync()
            {
                bool downloaded = await DownloadListFileAsync();
                if (downloaded)
                {
                    LoadFromFile();
                    await ResolveHostnamesAsync();
                    return true;
                }

                // even if file didn't change, re-resolve hostnames if interval elapsed
                if (_resolveIntervalSeconds > 0 && DateTime.UtcNow > _lastResolved.AddSeconds(_resolveIntervalSeconds))
                {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [" + _listUrl.AbsoluteUri + "] Re-resolving hostnames (interval elapsed)");
                    await ResolveHostnamesAsync();
                }

                return false;
            }

            async Task ResolveHostnamesAsync()
            {
                string[] hosts;
                lock (_lock)
                {
                    hosts = new string[_hostnames.Count];
                    _hostnames.CopyTo(hosts);
                }

                if (hosts.Length == 0)
                {
                    _lastResolved = DateTime.UtcNow;
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [" + _listUrl.AbsoluteUri + "] No hostnames to resolve.");
                    return;
                }

                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [" + _listUrl.AbsoluteUri + "] Resolving " + hosts.Length + " hostnames...");

                var newIps = new HashSet<IPAddress>();
                var tasks = new List<Task>();

                foreach (string host in hosts)
                {
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            if (_resolveDnsServers is not null && _resolveDnsServers.Length > 0)
                            {
                                DnsClient client = new DnsClient(_resolveDnsServers);
                                client.Proxy = _dnsServer.Proxy;
                                client.PreferIPv6 = _dnsServer.PreferIPv6;
                                try
                                {
                                    var aResp = await client.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN));
                                    foreach (var a in DnsClient.ParseResponseA(aResp))
                                    {
                                        lock (newIps) newIps.Add(a);
                                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Resolved " + host + " -> " + a);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: A resolve failed for " + host + ": " + ex.Message);
                                }
                                try
                                {
                                    var aaaaResp = await client.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN));
                                    foreach (var a in DnsClient.ParseResponseAAAA(aaaaResp))
                                    {
                                        lock (newIps) newIps.Add(a);
                                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Resolved " + host + " -> " + a);
                                    }
                                }
                                catch { }
                            }
                            else
                            {
                                try
                                {
                                    var aResp = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), 5000);
                                    foreach (var a in DnsClient.ParseResponseA(aResp))
                                    {
                                        lock (newIps) newIps.Add(a);
                                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Resolved " + host + " -> " + a);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: A resolve failed for " + host + ": " + ex.Message);
                                }
                                try
                                {
                                    var aaaaResp = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN), 5000);
                                    foreach (var a in DnsClient.ParseResponseAAAA(aaaaResp))
                                    {
                                        lock (newIps) newIps.Add(a);
                                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Resolved " + host + " -> " + a);
                                    }
                                }
                                catch { }
                            }
                        }
                        catch (Exception ex)
                        {
                            try { _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Resolve fail " + host + " => " + ex.ToString()); } catch { }
                        }
                    }));
                }

                try { await Task.WhenAll(tasks); } catch { }

                lock (_lock)
                {
                    foreach (var ip in newIps)
                        _resolvedIps.Add(ip);
                    _lastResolved = DateTime.UtcNow;
                }

                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [" + _listUrl.AbsoluteUri + "] Resolve complete. Total IPs now: " + IpCount);
            }

            public bool IsIpFound(IPAddress ip)
            {
                lock (_lock)
                {
                    return _resolvedIps.Contains(ip);
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