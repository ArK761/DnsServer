/*
 AdvancedBlockingWithUrlList
 New app that supports URL-based IP lists (each line an IP or hostname).
 Hostnames can be resolved periodically and with optional per-list DNS servers.
 This file is intentionally written to be a standalone app (namespace AdvancedBlockingWithUrlList)
 so it doesn't modify the existing AdvancedBlockingApp.
*/

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace AdvancedBlockingWithUrlList
{
    // Minimal "app" implementing core features. It follows existing repository patterns
    // but focuses on adding IpList support and wiring it into group selection.
    public sealed class App : IDnsApplication, IDisposable
    {
        IDnsServer? _dnsServer;

        bool _enableBlocking = true;
        uint _blockingAnswerTtl = 30;

        Dictionary<EndPoint, string>? _localEndPointGroupMap;
        Dictionary<NetworkAddress, string>? _networkGroupMap;
        Dictionary<string, Group>? _groups;

        Dictionary<Uri, IpList> _allIpListZones = new Dictionary<Uri, IpList>();

        Timer? _updateTimer;
        DateTime _lastUpdate = DateTime.UtcNow;

        const int UPDATE_CHECK_INTERVAL_MS = 60 * 1000; // 1 minute

        public void Dispose()
        {
            _updateTimer?.Dispose();
            _updateTimer = null;
        }

        public string Description => "AdvancedBlockingWithUrlList: Blocking with URL-based IP lists (IP or hostname lines) with optional per-list DNS and resolve interval.";

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;

            // parse config
            JsonDocument doc = JsonDocument.Parse(config);
            JsonElement root = doc.RootElement;

            _enableBlocking = root.GetPropertyValue("enableBlocking", true);
            _blockingAnswerTtl = root.GetPropertyValue("blockingAnswerTtl", 30u);

            // local endpoint map (optional)
            if (root.TryGetProperty("localEndPointGroupMap", out JsonElement localEPMap) && localEPMap.ValueKind == JsonValueKind.Object)
            {
                var map = new Dictionary<EndPoint, string>();
                foreach (JsonProperty p in localEPMap.EnumerateObject())
                {
                    // expecting "address:port": "group"
                    string key = p.Name;
                    string value = p.Value.GetString() ?? "";
                    // Try simple parse: ip:port or host:port
                    try
                    {
                        if (IPEndPoint.TryParse(key, out IPEndPoint? ipep))
                            map[ipep] = value;
                        else
                        {
                            // domain:port or plain
                            string[] parts = key.Split(':', 2);
                            if (parts.Length == 2 && int.TryParse(parts[1], out int port))
                                map[new DnsEndPoint(parts[0], port)] = value;
                        }
                    }
                    catch { }
                }
                _localEndPointGroupMap = map;
            }

            // networkGroupMap (optional)
            if (root.TryGetProperty("networkGroupMap", out JsonElement networkMap) && networkMap.ValueKind == JsonValueKind.Object)
            {
                var map = new Dictionary<NetworkAddress, string>();
                foreach (JsonProperty p in networkMap.EnumerateObject())
                {
                    string key = p.Name;
                    string value = p.Value.GetString() ?? "";
                    if (NetworkAddress.TryParse(key, out NetworkAddress na))
                        map[na] = value;
                }
                _networkGroupMap = map;
            }

            // parse groups
            if (root.TryGetProperty("groups", out JsonElement groupsElement) && groupsElement.ValueKind == JsonValueKind.Array)
            {
                var groups = new Dictionary<string, Group>();

                foreach (JsonElement ge in groupsElement.EnumerateArray())
                {
                    Group g = new Group(this, ge);
                    groups[g.Name] = g;
                }

                // Build shared ip-list instances for distinct URIs
                var ipLists = new Dictionary<Uri, IpList>();
                foreach (var kv in groups)
                {
                    foreach (UrlEntry ue in kv.Value.IpListUrls)
                    {
                        if (ue.Uri is null)
                            continue;
                        if (!ipLists.ContainsKey(ue.Uri))
                        {
                            var iplist = new IpList(_dnsServer, ue.Uri, ue.ResolveIntervalSeconds == 0 ? 3600 : ue.ResolveIntervalSeconds, ue.ResolveDnsServers);
                            ipLists[ue.Uri] = iplist;
                        }
                    }
                }

                _allIpListZones = ipLists;

                // let each group resolve their zone entries mapping to instances
                foreach (var kv in groups)
                {
                    kv.Value.LoadListZones(_allIpListZones);
                }

                _groups = groups;
            }

            // schedule periodic updates (download + optional resolves)
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
            }, null, UPDATE_CHECK_INTERVAL_MS, UPDATE_CHECK_INTERVAL_MS);
        }

        async Task UpdateAllAsync()
        {
            // Download/update all ip lists
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
            // For compatibility, IsAllowed returns false when not blocked (allowed).
            if (!_enableBlocking)
                return Task.FromResult(true);

            string? group = GetGroupName(request, remoteEP);
            if (group is null) return Task.FromResult(true);
            if (_groups is null || !_groups.TryGetValue(group, out Group? g)) return Task.FromResult(true);

            // Simple check: if group enabled and zone is blocked, disallow (return false)
            DnsQuestionRecord q = request.Question[0];
            if (g.IsZoneBlocked(q.Name, out _, out _, out _))
                return Task.FromResult(false);
            return Task.FromResult(true);
        }

        public Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            // If blocked, return blocking response (simple NXDOMAIN or provided addresses).
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram?>(null);

            string? group = GetGroupName(request, remoteEP);
            if (group is null) return Task.FromResult<DnsDatagram?>(null);
            if (_groups is null || !_groups.TryGetValue(group, out Group? g)) return Task.FromResult<DnsDatagram?>(null);

            DnsQuestionRecord q = request.Question[0];
            if (!g.IsZoneBlocked(q.Name, out string? blockedDomain, out string? blockedRegex, out UrlEntry? blockUrl))
                return Task.FromResult<DnsDatagram?>(null);

            // Return NXDOMAIN (simple)
            DnsResourceRecord[]? auth = null;
            var soa = new DnsSOARecordData(_dnsServer!.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 3600, 600, 86400, _blockingAnswerTtl);
            auth = new DnsResourceRecord[] { new DnsResourceRecord(q.Name, DnsResourceRecordType.SOA, q.Class, _blockingAnswerTtl, soa) };
            var resp = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NxDomain, request.Question, null, auth);
            return Task.FromResult<DnsDatagram?>(resp);
        }

        // Determine group by local endpoint mapping, ip-lists, then network map
        string? GetGroupName(DnsDatagram request, IPEndPoint remoteEP)
        {
            // check local endpoint map (if available)
            if (_localEndPointGroupMap is not null && request.Metadata is not null)
            {
                // simplified: iterate map for any matching endpoints; exact matching logic may be extended
                foreach (var kv in _localEndPointGroupMap)
                {
                    if (kv.Key is IPEndPoint ipep && request.Metadata.NameServer?.IPEndPoint is not null)
                    {
                        if (ipep.Address.Equals(request.Metadata.NameServer.IPEndPoint.Address))
                            return kv.Value;
                    }
                }
            }

            // check per-group ip lists first
            if (_groups is not null)
            {
                foreach (var g in _groups)
                {
                    try
                    {
                        if (g.Value.IsClientInIpLists(remoteEP.Address))
                            return g.Key;
                    }
                    catch { }
                }
            }

            // then check networkGroupMap
            if (_networkGroupMap is not null)
            {
                NetworkAddress? selected = null;
                string? name = null;
                foreach (var kv in _networkGroupMap)
                {
                    if (kv.Key.Contains(remoteEP.Address))
                    {
                        if (selected is null || kv.Key.PrefixLength > selected.PrefixLength)
                        {
                            selected = kv.Key;
                            name = kv.Value;
                        }
                    }
                }
                return name;
            }

            return null;
        }

        // --------------------
        // Helper / nested types
        // --------------------

        // UrlEntry supports either string url or object { url, resolveIntervalSeconds, resolveDnsServers }
        class UrlEntry
        {
            public Uri? Uri { get; }
            public int ResolveIntervalSeconds { get; }
            public IPAddress[]? ResolveDnsServers { get; }
            public bool BlockAsNxDomain { get; }

            public UrlEntry(JsonElement el)
            {
                if (el.ValueKind == JsonValueKind.String)
                {
                    Uri = new Uri(el.GetString()!);
                    ResolveIntervalSeconds = 0;
                    ResolveDnsServers = null;
                    BlockAsNxDomain = false;
                }
                else
                {
                    Uri = new Uri(el.GetProperty("url").GetString()!);
                    ResolveIntervalSeconds = el.GetPropertyValue("resolveIntervalSeconds", 0);
                    BlockAsNxDomain = el.GetPropertyValue("blockAsNxDomain", false);
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

            public UrlEntry(Uri uri)
            {
                Uri = uri;
                ResolveIntervalSeconds = 0;
                ResolveDnsServers = null;
                BlockAsNxDomain = false;
            }
        }

        class Group
        {
            readonly App _app;
            public string Name { get; }
            public bool EnableBlocking { get; }
            public bool BlockAsNxDomain { get; }

            public UrlEntry[] IpListUrls { get; }

            Dictionary<Uri, IpList> _ipListZones = new Dictionary<Uri, IpList>();

            // minimal allowed/blocked structures for blocking by zone name
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
                        entries.Add(new UrlEntry(el));
                    IpListUrls = entries.ToArray();
                }
                else
                    IpListUrls = Array.Empty<UrlEntry>();

                // optional blocked domains
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

            public void LoadListZones(Dictionary<Uri, IpList> allIpLists)
            {
                foreach (var ue in IpListUrls)
                {
                    if (ue.Uri is null) continue;
                    if (allIpLists.TryGetValue(ue.Uri, out IpList? ipList))
                        _ipListZones[ue.Uri] = ipList;
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

        // Minimal ListBase: downloads file and tracks last modified; used by IpList.
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

        // IpList: parses file lines (IP or hostname) and optionally resolves hostnames.
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
                // if file not present, try to download once
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
                            // prefer A and AAAA based on server preference
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
