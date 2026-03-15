/*
 AdvancedBlockingWithUrlList
 Supports:
  - ipListMaps (URL -> name)
  - ipListUrls in groups can reference either URL or name from ipListMaps
  - global refresh interval (minutes) via blockListUrlUpdateIntervalMinutes
  - global resolve interval (seconds) via ipListResolveIntervalSeconds
  - global resolve DNS servers via ipListResolveDnsServers
  - removed networkGroupMap and localEndPointGroupMap
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

        public string Description => "AdvancedBlockingWithUrlList: URL-based IP lists with global refresh and resolve settings. No local/network maps.";

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

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
                            // create IpList instance for this url (use global resolve interval/dns)
                            if (!_allIpListZones.ContainsKey(u))
                            {
                                var iplist = new IpList(_dnsServer, u, _globalResolveIntervalSeconds, _globalResolveDnsServers);
                                _allIpListZones[u] = iplist;
                                // initial load async (fire and forget safe)
                                _ = iplist.LoadAsync();
                            }
                        }
                        catch { }
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
                }

                // resolve ipListUrls in each group and ensure IpList instances exist
                foreach (var kv in groups)
                {
                    kv.Value.LoadListZones(_allIpListZones, _nameToUrlMap, _globalResolveIntervalSeconds, _globalResolveDnsServers);
                }

                _groups = groups;
            }

            // schedule periodic updates (download + optional resolves) using minutes interval
            var due = TimeSpan.FromMinutes(Math.Max(1, _refreshIntervalMinutes));
            _updateTimer = new Timer(async _ =>
            {
                try
                {
                    await UpdateAllAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer?.WriteLog(ex);
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

            // Determine group only by client IP membership in ip lists
            if (_groups is not null)
            {
                foreach (var kv in _groups)
                {
                    try
                    {
                        if (kv.Value.IsClientInIpLists(remoteEP.Address))
                            return Task.FromResult(!kv.Value.EnableBlocking ? true : false);
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
                    DnsQuestionRecord q = request.Question[0];
                    if (g.IsZoneBlocked(q.Name, out _, out _, out _))
                    {
                        var soa = new DnsSOARecordData(_dnsServer!.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 3600, 600, 86400, _blockingAnswerTtl);
                        var auth = new DnsResourceRecord[] { new DnsResourceRecord(q.Name, DnsResourceRecordType.SOA, q.Class, _blockingAnswerTtl, soa) };
                        var resp = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NxDomain, request.Question, null, auth);
                        return Task.FromResult<DnsDatagram?>(resp);
                    }
                }
            }

            return Task.FromResult<DnsDatagram?>(null);
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

            // ip list references: can be URL, name (resolved via ipListMaps) or per-list object
            public UrlEntry[] IpListUrls { get; }

            Dictionary<Uri, IpList> _ipListZones = new Dictionary<Uri, IpList>(UriComparer.Instance);

            HashSet<string> _blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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

                if (json.TryGetProperty("blocked", out JsonElement blocked) && blocked.ValueKind == JsonValueKind.Array)
                {
                    foreach (var b in blocked.EnumerateArray())
                    {
                        string? s = b.GetString();
                        if (!string.IsNullOrEmpty(s))
                            _blocked.Add(s.ToLowerInvariant());
                    }
                }
            }

            // load mapping from global allIpLists (ensure instances exist for each referenced URL)
            public void LoadListZones(Dictionary<Uri, IpList> allIpLists, Dictionary<string, Uri> nameToUrlMap, int globalResolveIntervalSeconds, IPAddress[]? globalResolveDnsServers)
            {
                foreach (var ue in IpListUrls)
                {
                    if (ue.IsName)
                    {
                        if (nameToUrlMap.TryGetValue(ue.Name!, out Uri? mappedUrl))
                        {
                            // if IpList for url not present in global map, create with global settings
                            if (!allIpLists.TryGetValue(mappedUrl, out IpList? ipList))
                            {
                                ipList = new IpList(_app._dnsServer!, mappedUrl, globalResolveIntervalSeconds, globalResolveDnsServers);
                                allIpListZones: ; // placeholder removed in final version
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
                            // if entry has custom resolve settings, use them; otherwise global
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

            public bool IsZoneBlocked(string domain, out string? blockedDomain, out string? blockedRegex, out UrlEntry? listUrl)
            {
                domain = domain.ToLowerInvariant();
                if (_blocked.Contains(domain))
                {
                    blockedDomain = domain;
                    blockedRegex = null;
                    listUrl = null;
                    return true;
                }
                blockedDomain = null; blockedRegex = null; listUrl = null;
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
                // raw could be name (List1) or direct URL
                if (Uri.TryCreate(raw, UriKind.Absolute, out Uri? u))
                {
                    Uri = u;
                    Name = null;
                    ResolveIntervalSeconds = 0;
                    ResolveDnsServers = null;
                }
                else
                {
                    // treat as name
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
                    if (Uri.TryCreate(s, UriKind.Absolute, out Uri? u))
                    {
                        Uri = u;
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
                    // object
                    string url = el.GetProperty("url").GetString()!;
                    Uri = Uri.TryCreate(url, UriKind.Absolute, out Uri? u2) ? u2 : null;
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

        // Minimal ListBase and IpList (same behavior as prior implementation, unchanged)
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
                    if (_listUrl.Scheme == "file")
                    {
                        string src = _listUrl.LocalPath;
                        if (!File.Exists(src)) return false;
                        DateTime srcTime = File.GetLastWriteTimeUtc(src);
                        if (File.Exists(_cachePath) && File.GetLastWriteTimeUtc(_cachePath) >= srcTime)
                            return false;
                        File.Copy(src, _cachePath, true);
                        LastModified = File.GetLastWriteTimeUtc(_cachePath);
                        return true;
                    }
                    else
                    {
                        using HttpClient http = new HttpClient();
                        http.Timeout = TimeSpan.FromSeconds(10);
                        using var resp = await http.GetAsync(_listUrl);
                        if (!resp.IsSuccessStatusCode) return false;
                        byte[] content = await resp.Content.ReadAsByteArrayAsync();
                        await File.WriteAllBytesAsync(_cachePath, content);
                        LastModified = DateTime.UtcNow;
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    try { _dnsServer.WriteLog("List download failed: " + _listUrl + " => " + ex.ToString()); } catch { }
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
                        ips.Add(ip);
                    else
                    {
                        string host = line.Trim().TrimEnd('.');
                        if (host.Length > 0)
                            hosts.Add(host);
                    }
                }

                lock (_lock)
                {
                    _resolvedIps = ips;
                    _hostnames = hosts;
                }
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

                if (_resolveIntervalSeconds > 0 && DateTime.UtcNow > _lastResolved.AddSeconds(_resolveIntervalSeconds))
                {
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
                    return;
                }

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
                                        lock (newIps) newIps.Add(a);
                                }
                                catch { }
                                try
                                {
                                    var aaaaResp = await client.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN));
                                    foreach (var a in DnsClient.ParseResponseAAAA(aaaaResp))
                                        lock (newIps) newIps.Add(a);
                                }
                                catch { }
                            }
                            else
                            {
                                try
                                {
                                    var aResp = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), 2000);
                                    foreach (var a in DnsClient.ParseResponseA(aResp))
                                        lock (newIps) newIps.Add(a);
                                }
                                catch { }
                                try
                                {
                                    var aaaaResp = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN), 2000);
                                    foreach (var a in DnsClient.ParseResponseAAAA(aaaaResp))
                                        lock (newIps) newIps.Add(a);
                                }
                                catch { }
                            }
                        }
                        catch (Exception ex)
                        {
                            try { _dnsServer.WriteLog("IpList resolve fail " + host + " => " + ex.ToString()); } catch { }
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
}
