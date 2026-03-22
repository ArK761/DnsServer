/*
 AdvancedBlockingWithUrlList - TestVersion000001
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
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
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
    public sealed class App : IDnsApplication, IDnsRequestBlockingHandler, IDisposable
    {
        IDnsServer? _dnsServer;
        bool _enableBlocking = true;
        uint _blockingAnswerTtl = 30;
        Dictionary<string, Group>? _groups;
        Dictionary<Uri, IpList> _allIpLists = new Dictionary<Uri, IpList>(UriComparer.Instance);
        Dictionary<string, Uri> _nameToUrlMap = new Dictionary<string, Uri>(StringComparer.OrdinalIgnoreCase);
        CancellationTokenSource? _cts;
        Task? _downloadTask;
        Task? _resolveTask;
        int _downloadIntervalMinutes = 5;
        int _downloadSleepSeconds = 30;
        int _resolveIntervalSeconds = 300;
        int _httpTimeoutSeconds = 30;
        IPAddress[]? _globalResolveDnsServers;
        static readonly HttpClient s_httpClient = new HttpClient();
        public string Description =>
            "AdvancedBlockingWithUrlList: URL-based client IP lists with named cache files and separate *_Resolve files for resolved hostnames.\n";
        public void Dispose()
        {
            StopWorkers();
        }
        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            StopWorkers();
            _allIpLists = new Dictionary<Uri, IpList>(UriComparer.Instance);
            _nameToUrlMap = new Dictionary<string, Uri>(StringComparer.OrdinalIgnoreCase);
            _groups = null;
            _cts = new CancellationTokenSource();
            JsonDocument doc = JsonDocument.Parse(config);
            JsonElement root = doc.RootElement;
            _enableBlocking = root.GetPropertyValue("enableBlocking", true);
            _blockingAnswerTtl = root.GetPropertyValue("blockingAnswerTtl", 30u);
            _downloadIntervalMinutes = Math.Max(1, root.GetPropertyValue("blockListUrlUpdateIntervalMinutes", 5));
            _downloadSleepSeconds = Math.Max(0, root.GetPropertyValue("blockListUrlUpdateSleepSeconds", 30));
            _resolveIntervalSeconds = Math.Max(300, root.GetPropertyValue("ipListResolveIntervalSeconds", 300));
            _httpTimeoutSeconds = Math.Max(5, root.GetPropertyValue("httpTimeoutSeconds", 30));
            _globalResolveDnsServers = ParseDnsServers(root, "ipListResolveDnsServers");
            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Initializing...");
            _dnsServer.WriteLog(
                "AdvancedBlockingWithUrlList: enableBlocking=" + _enableBlocking +
                " downloadMin=" + _downloadIntervalMinutes +
                " downloadSleepSec=" + _downloadSleepSeconds +
                " resolveSec=" + _resolveIntervalSeconds +
                " httpTimeoutSec=" + _httpTimeoutSeconds
            );
            if (root.TryGetProperty("ipListMaps", out JsonElement mapsElem) && mapsElem.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty p in mapsElem.EnumerateObject())
                {
                    string urlText = p.Name;
                    string listName = (p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : null) ?? string.Empty;
                    listName = listName.Trim();
                    if (listName.Length == 0)
                    {
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Skipping ipListMaps entry with empty name for URL=" + urlText);
                        continue;
                    }
                    if (!Uri.TryCreate(urlText, UriKind.Absolute, out Uri? listUrl))
                    {
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Skipping invalid URL in ipListMaps: " + urlText);
                        continue;
                    }
                    if (_nameToUrlMap.ContainsKey(listName))
                    {
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Duplicate ipListMaps logical name ignored: " + listName);
                        continue;
                    }
                    _nameToUrlMap[listName] = listUrl;
                    if (_allIpLists.ContainsKey(listUrl))
                        continue;
                    var ipList = new IpList(_dnsServer, listUrl, listName, _httpTimeoutSeconds, _globalResolveDnsServers);
                    _allIpLists[listUrl] = ipList;
                    _dnsServer.WriteLog(
                        "AdvancedBlockingWithUrlList: Creating IpList URL=" + listUrl.AbsoluteUri +
                        " name=" + listName +
                        " rawFile=" + ipList.RawFileName +
                        " resolveFile=" + ipList.ResolveFileName
                    );
                    try
                    {
                        await ipList.DownloadAndParseAsync().ConfigureAwait(false);
                        await ipList.ResolveHostnamesAsync().ConfigureAwait(false);
                        _dnsServer.WriteLog(
                            "AdvancedBlockingWithUrlList: Loaded " + listName +
                            " directIPs=" + ipList.DirectIpCount +
                            " hostnames=" + ipList.HostnameCount +
                            " resolvedIPs=" + ipList.ResolvedIpCount +
                            " totalIPs=" + ipList.TotalIpCount
                        );
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Failed initial load for " + listName + ": " + ex.Message);
                    }
                }
            }
            if (root.TryGetProperty("groups", out JsonElement groupsElement) && groupsElement.ValueKind == JsonValueKind.Array)
            {
                var groups = new Dictionary<string, Group>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonElement ge in groupsElement.EnumerateArray())
                {
                    Group g = new Group(this, ge);
                    groups[g.Name] = g;
                    if (_nameToUrlMap.TryGetValue(g.Name, out Uri? mappedUrl) && _allIpLists.TryGetValue(mappedUrl, out IpList? mappedList))
                    {
                        g.AddIpListZone(mappedUrl, mappedList);
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Group '" + g.Name + "' auto-linked to URL=" + mappedUrl.AbsoluteUri);
                    }
                    g.LoadListZones(_allIpLists, _nameToUrlMap);
                }
                _groups = groups;
            }
            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: IDnsRequestBlockingHandler active.");
            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: Init complete. Groups=" + (_groups?.Count ?? 0) + " IpLists=" + _allIpLists.Count);
            CancellationToken ct = _cts.Token;
            _downloadTask = Task.Run(() => DownloadLoopAsync(ct), ct);
            _resolveTask = Task.Run(() => ResolveLoopAsync(ct), ct);
        }
        void StopWorkers()
        {
            try
            {
                _cts?.Cancel();
                if (_downloadTask != null)
                {
                    try { _downloadTask.Wait(TimeSpan.FromSeconds(5)); } catch { }
                    _downloadTask = null;
                }
                if (_resolveTask != null)
                {
                    try { _resolveTask.Wait(TimeSpan.FromSeconds(5)); } catch { }
                    _resolveTask = null;
                }
            }
            finally
            {
                _cts?.Dispose();
                _cts = null;
            }
        }
        async Task DownloadLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(_downloadIntervalMinutes), cancellationToken).ConfigureAwait(false);
                while (!cancellationToken.IsCancellationRequested)
                {
                    int i = 0;
                    foreach (var kv in _allIpLists)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (i > 0 && _downloadSleepSeconds > 0)
                            await Task.Delay(TimeSpan.FromSeconds(_downloadSleepSeconds), cancellationToken).ConfigureAwait(false);
                        try
                        {
                            bool changed = await kv.Value.DownloadAndParseAsync().ConfigureAwait(false);
                            if (changed)
                            {
                                _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Download] Content changed, re-resolving " + kv.Value.DisplayName);
                                await kv.Value.ResolveHostnamesAsync().ConfigureAwait(false);
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [Download] Error for " + kv.Value.DisplayName + ": " + ex.Message);
                        }
                        i++;
                    }
                    await Task.Delay(TimeSpan.FromMinutes(_downloadIntervalMinutes), cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: Download loop stopped: " + ex.Message);
            }
        }
        async Task ResolveLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(_resolveIntervalSeconds), cancellationToken).ConfigureAwait(false);
                while (!cancellationToken.IsCancellationRequested)
                {
                    foreach (var kv in _allIpLists)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        try
                        {
                            await kv.Value.ResolveHostnamesAsync().ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: [ResolveLoop] Error for " + kv.Value.DisplayName + ": " + ex.Message);
                        }
                    }
                    await Task.Delay(TimeSpan.FromSeconds(_resolveIntervalSeconds), cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: Resolve loop stopped: " + ex.Message);
            }
        }
        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult(true);
            IPAddress clientIp = NormalizeClientIp(remoteEP.Address);
            if (_groups is not null)
            {
                foreach (Group group in _groups.Values)
                {
                    try
                    {
                        if (!group.IsClientInIpLists(clientIp))
                            continue;
                        if (!group.EnableBlocking)
                            return Task.FromResult(true);
                        return Task.FromResult(false);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: IsAllowed check failed: " + ex.Message);
                    }
                }
            }
            return Task.FromResult(false);
        }
        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (!_enableBlocking)
                return Task.FromResult<DnsDatagram>(null);
            if (request == null || request.Question == null || request.Question.Count == 0)
                return Task.FromResult<DnsDatagram>(null);
            IPAddress clientIp = NormalizeClientIp(remoteEP.Address);
            DnsQuestionRecord q = request.Question[0];
            string domain = (q.Name ?? string.Empty).TrimEnd('.');
            if (_groups is not null)
            {
                foreach (Group group in _groups.Values)
                {
                    try
                    {
                        if (!group.EnableBlocking)
                            continue;
                        if (!group.IsClientInIpLists(clientIp))
                            continue;
                        if (group.IsZoneAllowed(domain) || group.IsZoneAllowedByRegex(domain))
                            return Task.FromResult<DnsDatagram>(null);
                        if (group.IsZoneBlocked(domain) || group.IsZoneBlockedByRegex(domain))
                        {
                            _dnsServer?.WriteLog(
                                "AdvancedBlockingWithUrlList: Blocked domain='" + domain +
                                "' client='" + clientIp +
                                "' group='" + group.Name + "'"
                            );
                            return Task.FromResult(CreateBlockedResponse(request, q));
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: ProcessRequest failed: " + ex.Message);
                    }
                }
            }
            return Task.FromResult<DnsDatagram>(null);
        }
        DnsDatagram CreateBlockedResponse(DnsDatagram request, DnsQuestionRecord q)
        {
            try
            {
                var soa = new DnsSOARecordData(
                    _dnsServer!.ServerDomain,
                    _dnsServer.ResponsiblePerson.Address,
                    1,
                    3600,
                    600,
                    86400,
                    _blockingAnswerTtl
                );
                var authority = new DnsResourceRecord[]
                {
                    new DnsResourceRecord(q.Name, DnsResourceRecordType.SOA, q.Class, _blockingAnswerTtl, soa)
                };
                return new DnsDatagram(
                    ID: request.Identifier,
                    isResponse: true,
                    OPCODE: DnsOpcode.StandardQuery,
                    authoritativeAnswer: true,
                    truncation: false,
                    recursionDesired: request.RecursionDesired,
                    recursionAvailable: _dnsServer != null,
                    authenticData: false,
                    checkingDisabled: false,
                    RCODE: DnsResponseCode.NxDomain,
                    question: request.Question,
                    answer: null,
                    authority: authority,
                    additional: null,
                    udpPayloadSize: request.EDNS is null ? ushort.MinValue : _dnsServer!.UdpPayloadSize,
                    ednsFlags: EDnsHeaderFlags.None,
                    options: null
                );
            }
            catch (Exception ex)
            {
                try
                {
                    _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: CreateBlockedResponse failed: " + ex.Message);
                }
                catch
                {
                }
                return new DnsDatagram(
                    request.Identifier,
                    true,
                    DnsOpcode.StandardQuery,
                    true,
                    false,
                    request.RecursionDesired,
                    false,
                    false,
                    false,
                    DnsResponseCode.NxDomain,
                    request.Question,
                    null
                );
            }
        }
        static IPAddress NormalizeClientIp(IPAddress ip)
        {
            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv4MappedToIPv6)
                return ip.MapToIPv4();
            return ip;
        }
        static IPAddress[]? ParseDnsServers(JsonElement root, string propertyName)
        {
            if (!root.TryGetProperty(propertyName, out JsonElement dnsServers) || dnsServers.ValueKind != JsonValueKind.Array)
                return null;
            var list = new List<IPAddress>();
            foreach (JsonElement j in dnsServers.EnumerateArray())
            {
                string? raw = j.GetString();
                if (IPAddress.TryParse(raw, out IPAddress? a))
                    list.Add(a);
            }
            return list.Count > 0 ? list.ToArray() : null;
        }
        static string SanitizeFileName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "List";
            var sb = new StringBuilder(value.Length);
            char[] invalid = Path.GetInvalidFileNameChars();
            foreach (char c in value.Trim())
            {
                if (invalid.Contains(c) || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
                    sb.Append('_');
                else
                    sb.Append(c);
            }
            string result = sb.ToString().Trim();
            return result.Length == 0 ? "List" : result;
        }
        sealed class UriComparer : IEqualityComparer<Uri>
        {
            public static readonly UriComparer Instance = new UriComparer();
            public bool Equals(Uri? x, Uri? y) =>
                StringComparer.OrdinalIgnoreCase.Equals(x?.AbsoluteUri, y?.AbsoluteUri);
            public int GetHashCode(Uri obj) =>
                obj is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(obj.AbsoluteUri);
        }
        sealed class Group
        {
            readonly App _app;
            readonly Dictionary<Uri, IpList> _ipListZones = new Dictionary<Uri, IpList>(UriComparer.Instance);
            readonly HashSet<string> _allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            readonly HashSet<string> _blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            readonly List<Regex> _allowedRegex = new List<Regex>();
            readonly List<Regex> _blockedRegex = new List<Regex>();
            public string Name { get; }
            public bool EnableBlocking { get; }
            public bool BlockAsNxDomain { get; }
            public UrlEntry[] IpListUrls { get; }
            public Group(App app, JsonElement json)
            {
                _app = app;
                Name = json.GetProperty("name").GetString() ?? "default";
                EnableBlocking = json.GetPropertyValue("enableBlocking", true);
                BlockAsNxDomain = json.GetPropertyValue("blockAsNxDomain", false);
                if (json.TryGetProperty("ipListUrls", out JsonElement ipListUrls) && ipListUrls.ValueKind == JsonValueKind.Array)
                {
                    var entries = new List<UrlEntry>();
                    foreach (JsonElement el in ipListUrls.EnumerateArray())
                    {
                        if (el.ValueKind == JsonValueKind.String)
                            entries.Add(new UrlEntry(el.GetString() ?? string.Empty));
                        else if (el.ValueKind == JsonValueKind.Object)
                            entries.Add(new UrlEntry(el));
                    }
                    IpListUrls = entries.ToArray();
                }
                else
                {
                    IpListUrls = Array.Empty<UrlEntry>();
                }
                LoadDomainSet(json, "allowed", _allowed);
                LoadDomainSet(json, "blocked", _blocked);
                LoadRegexSet(json, "allowedRegex", _allowedRegex);
                LoadRegexSet(json, "blockedRegex", _blockedRegex);
            }
            void LoadDomainSet(JsonElement json, string propertyName, HashSet<string> target)
            {
                if (!json.TryGetProperty(propertyName, out JsonElement arr) || arr.ValueKind != JsonValueKind.Array)
                    return;
                foreach (JsonElement item in arr.EnumerateArray())
                {
                    string? s = item.GetString();
                    if (string.IsNullOrWhiteSpace(s))
                        continue;
                    target.Add(s.Trim().TrimEnd('.').ToLowerInvariant());
                }
            }
            void LoadRegexSet(JsonElement json, string propertyName, List<Regex> target)
            {
                if (!json.TryGetProperty(propertyName, out JsonElement arr) || arr.ValueKind != JsonValueKind.Array)
                    return;
                foreach (JsonElement item in arr.EnumerateArray())
                {
                    string? pattern = item.GetString();
                    if (string.IsNullOrWhiteSpace(pattern))
                        continue;
                    try
                    {
                        target.Add(new Regex(
                            pattern,
                            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline
                        ));
                    }
                    catch (Exception ex)
                    {
                        _app._dnsServer?.WriteLog("AdvancedBlockingWithUrlList: Invalid regex '" + pattern + "': " + ex.Message);
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
                foreach (UrlEntry entry in IpListUrls)
                {
                    if (entry.IsName)
                    {
                        if (nameToUrlMap.TryGetValue(entry.Name!, out Uri? mappedUrl) && allIpLists.TryGetValue(mappedUrl, out IpList? mappedList))
                            _ipListZones[mappedUrl] = mappedList;
                    }
                    else if (entry.Uri is not null)
                    {
                        if (allIpLists.TryGetValue(entry.Uri, out IpList? mappedList))
                            _ipListZones[entry.Uri] = mappedList;
                    }
                }
            }
            public bool IsClientInIpLists(IPAddress ip)
            {
                foreach (IpList list in _ipListZones.Values)
                {
                    try
                    {
                        if (list.IsIpFound(ip))
                            return true;
                    }
                    catch (Exception ex)
                    {
                        _app._dnsServer?.WriteLog("AdvancedBlockingWithUrlList: IsClientInIpLists error: " + ex.Message);
                    }
                }
                return false;
            }
            public bool IsZoneAllowed(string domain)
            {
                domain = NormalizeDomain(domain);
                return _allowed.Contains(domain);
            }
            public bool IsZoneBlocked(string domain)
            {
                domain = NormalizeDomain(domain);
                return _blocked.Contains(domain);
            }
            public bool IsZoneAllowedByRegex(string domain)
            {
                domain = NormalizeDomain(domain);
                foreach (Regex rx in _allowedRegex)
                {
                    try
                    {
                        if (rx.IsMatch(domain))
                            return true;
                    }
                    catch (Exception ex)
                    {
                        _app._dnsServer?.WriteLog("AdvancedBlockingWithUrlList: allow regex match failed: " + ex.Message);
                    }
                }
                return false;
            }
            public bool IsZoneBlockedByRegex(string domain)
            {
                domain = NormalizeDomain(domain);
                foreach (Regex rx in _blockedRegex)
                {
                    try
                    {
                        if (rx.IsMatch(domain))
                            return true;
                    }
                    catch (Exception ex)
                    {
                        _app._dnsServer?.WriteLog("AdvancedBlockingWithUrlList: block regex match failed: " + ex.Message);
                    }
                }
                return false;
            }
            static string NormalizeDomain(string domain) =>
                (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        }
        sealed class UrlEntry
        {
            public Uri? Uri { get; }
            public string? Name { get; }
            public bool IsName => Name is not null;
            public UrlEntry(string raw)
            {
                raw = (raw ?? string.Empty).Trim();
                if (System.Uri.TryCreate(raw, UriKind.Absolute, out Uri? url))
                {
                    Uri = url;
                    Name = null;
                }
                else
                {
                    Name = raw;
                    Uri = null;
                }
            }
            public UrlEntry(JsonElement el)
            {
                string? raw = null;
                if (el.TryGetProperty("name", out JsonElement nameEl) && nameEl.ValueKind == JsonValueKind.String)
                    raw = nameEl.GetString();
                else if (el.TryGetProperty("url", out JsonElement urlEl) && urlEl.ValueKind == JsonValueKind.String)
                    raw = urlEl.GetString();
                else if (el.TryGetProperty("value", out JsonElement valueEl) && valueEl.ValueKind == JsonValueKind.String)
                    raw = valueEl.GetString();
                raw = (raw ?? string.Empty).Trim();
                if (System.Uri.TryCreate(raw, UriKind.Absolute, out Uri? url))
                {
                    Uri = url;
                    Name = null;
                }
                else
                {
                    Name = raw;
                    Uri = null;
                }
            }
        }
        abstract class ListBase
        {
            protected readonly IDnsServer _dnsServer;
            protected readonly Uri _listUrl;
            protected readonly string _cachePath;
            protected readonly int _httpTimeoutSeconds;
            public string DisplayName { get; }
            public string RawFileName => Path.GetFileName(_cachePath);
            public DateTime LastModified { get; protected set; } = DateTime.MinValue;
            protected ListBase(IDnsServer dnsServer, Uri listUrl, string displayName, int httpTimeoutSeconds)
            {
                _dnsServer = dnsServer;
                _listUrl = listUrl;
                _httpTimeoutSeconds = httpTimeoutSeconds;
                DisplayName = displayName;
                string listsFolder = Path.Combine(_dnsServer.ApplicationFolder, "lists");
                Directory.CreateDirectory(listsFolder);
                _cachePath = Path.Combine(listsFolder, SanitizeFileName(displayName));
            }
            protected async Task<bool> DownloadListFileAsync()
            {
                try
                {
                    if (_listUrl.Scheme.Equals("file", StringComparison.OrdinalIgnoreCase))
                    {
                        string src = _listUrl.LocalPath;
                        if (!File.Exists(src))
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] File not found: " + src);
                            return false;
                        }
                        byte[] newContent = await File.ReadAllBytesAsync(src).ConfigureAwait(false);
                        bool changed = await WriteIfDifferentAsync(_cachePath, newContent).ConfigureAwait(false);
                        if (changed)
                        {
                            LastModified = File.GetLastWriteTimeUtc(src);
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] File changed -> " + RawFileName);
                        }
                        return changed;
                    }
                    else
                    {
                        using var req = new HttpRequestMessage(HttpMethod.Get, _listUrl);
                        if (File.Exists(_cachePath) && LastModified > DateTime.MinValue)
                            req.Headers.IfModifiedSince = new DateTimeOffset(DateTime.SpecifyKind(LastModified, DateTimeKind.Utc));
                        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_httpTimeoutSeconds));
                        using HttpResponseMessage resp = await s_httpClient.SendAsync(req, cts.Token).ConfigureAwait(false);
                        if (resp.StatusCode == HttpStatusCode.NotModified)
                            return false;
                        if (!resp.IsSuccessStatusCode)
                        {
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] HTTP " + (int)resp.StatusCode + " for " + _listUrl.AbsoluteUri);
                            return false;
                        }
                        byte[] newContent = await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                        bool changed = await WriteIfDifferentAsync(_cachePath, newContent).ConfigureAwait(false);
                        if (changed)
                        {
                            LastModified = resp.Content.Headers.LastModified?.UtcDateTime ?? DateTime.UtcNow;
                            _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] Changed -> " + RawFileName + " from " + _listUrl.AbsoluteUri);
                        }
                        return changed;
                    }
                }
                catch (OperationCanceledException)
                {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] Timeout for " + _listUrl.AbsoluteUri);
                    return false;
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Download] Error for " + _listUrl.AbsoluteUri + ": " + ex.Message);
                    return false;
                }
            }
            static async Task<bool> WriteIfDifferentAsync(string path, byte[] newContent)
            {
                if (File.Exists(path))
                {
                    byte[] oldContent = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
                    if (oldContent.Length == newContent.Length)
                    {
                        bool same = true;
                        for (int i = 0; i < oldContent.Length; i++)
                        {
                            if (oldContent[i] != newContent[i])
                            {
                                same = false;
                                break;
                            }
                        }
                        if (same)
                            return false;
                    }
                }
                await File.WriteAllBytesAsync(path, newContent).ConfigureAwait(false);
                return true;
            }
            protected IEnumerable<string> ReadListLines()
            {
                if (!File.Exists(_cachePath))
                    yield break;
                using var sr = new StreamReader(_cachePath, Encoding.UTF8);
                string? line;
                while ((line = sr.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.Length == 0)
                        continue;
                    if (line.StartsWith("#") || line.StartsWith("!"))
                        continue;
                    yield return line;
                }
            }
        }
        sealed class IpList : ListBase
        {
            const int RESOLVE_BATCH_SIZE = 10;
            readonly IPAddress[]? _resolveDnsServers;
            readonly string _resolvedPath;
            readonly object _lock = new object();
            HashSet<IPAddress> _directIps = new HashSet<IPAddress>();
            HashSet<string> _hostnames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<IPAddress> _resolvedIps = new HashSet<IPAddress>();
            public string ResolveFileName => Path.GetFileName(_resolvedPath);
            public int DirectIpCount { get { lock (_lock) { return _directIps.Count; } } }
            public int HostnameCount { get { lock (_lock) { return _hostnames.Count; } } }
            public int ResolvedIpCount { get { lock (_lock) { return _resolvedIps.Count; } } }
            public int TotalIpCount { get { lock (_lock) { return _directIps.Count + _resolvedIps.Count; } } }
            public IpList(IDnsServer dnsServer, Uri listUrl, string displayName, int httpTimeoutSeconds, IPAddress[]? resolveDnsServers)
                : base(dnsServer, listUrl, displayName, httpTimeoutSeconds)
            {
                _resolveDnsServers = resolveDnsServers;
                _resolvedPath = Path.Combine(Path.GetDirectoryName(_cachePath)!, SanitizeFileName(displayName) + "_Resolve");
            }
            public async Task<bool> DownloadAndParseAsync()
            {
                bool changed = await DownloadListFileAsync().ConfigureAwait(false);
                if (!changed)
                {
                    lock (_lock)
                    {
                        if ((_directIps.Count > 0 || _hostnames.Count > 0) || !File.Exists(_cachePath))
                            return false;
                    }
                }
                ParsePrimaryFile();
                LoadResolvedFileIntoMemory();
                return changed;
            }
            void ParsePrimaryFile()
            {
                var ips = new HashSet<IPAddress>();
                var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (string line in ReadListLines())
                {
                    string value = line.Trim();
                    if (IPAddress.TryParse(value, out IPAddress? ip))
                    {
                        ips.Add(NormalizeIp(ip));
                    }
                    else
                    {
                        string host = value.TrimEnd('.');
                        if (host.Length > 0)
                            hosts.Add(host);
                    }
                }
                lock (_lock)
                {
                    _directIps = ips;
                    _hostnames = hosts;
                }
                _dnsServer.WriteLog(
                    "AdvancedBlockingWithUrlList: [Parse] " + DisplayName +
                    " => directIPs=" + ips.Count +
                    " hostnames=" + hosts.Count +
                    " rawFile=" + RawFileName
                );
            }
            void LoadResolvedFileIntoMemory()
            {
                var resolved = new HashSet<IPAddress>();
                try
                {
                    if (File.Exists(_resolvedPath))
                    {
                        foreach (string line in File.ReadLines(_resolvedPath))
                        {
                            string value = line.Trim();
                            if (IPAddress.TryParse(value, out IPAddress? ip))
                                resolved.Add(NormalizeIp(ip));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [ResolveLoad] Failed for " + ResolveFileName + ": " + ex.Message);
                }
                lock (_lock)
                {
                    _resolvedIps = resolved;
                }
            }
            public async Task ResolveHostnamesAsync()
            {
                string[] hosts;
                lock (_lock)
                {
                    hosts = _hostnames.ToArray();
                }
                if (hosts.Length == 0)
                {
                    lock (_lock)
                    {
                        _resolvedIps = new HashSet<IPAddress>();
                    }
                    await WriteResolvedFileAsync(Array.Empty<IPAddress>()).ConfigureAwait(false);
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] " + DisplayName + " no hostnames. Cleared " + ResolveFileName);
                    return;
                }
                _dnsServer.WriteLog(
                    "AdvancedBlockingWithUrlList: [Resolve] " + DisplayName +
                    " resolving " + hosts.Length + " hostnames into " + ResolveFileName
                );
                var newResolved = new HashSet<IPAddress>();
                int batchNum = 0;
                for (int offset = 0; offset < hosts.Length; offset += RESOLVE_BATCH_SIZE)
                {
                    int count = Math.Min(RESOLVE_BATCH_SIZE, hosts.Length - offset);
                    var batchTasks = new List<Task>(count);
                    batchNum++;
                    for (int j = 0; j < count; j++)
                    {
                        string host = hosts[offset + j];
                        batchTasks.Add(ResolveOneHostAsync(host, newResolved));
                    }
                    try
                    {
                        await Task.WhenAll(batchTasks).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] Batch error for " + DisplayName + ": " + ex.Message);
                    }
                    _dnsServer.WriteLog(
                        "AdvancedBlockingWithUrlList: [Resolve] " + DisplayName +
                        " batch=" + batchNum +
                        " hosts=" + count +
                        " resolvedSoFar=" + newResolved.Count
                    );
                }
                lock (_lock)
                {
                    _resolvedIps = newResolved;
                }
                await WriteResolvedFileAsync(newResolved).ConfigureAwait(false);
                _dnsServer.WriteLog(
                    "AdvancedBlockingWithUrlList: [Resolve] " + DisplayName +
                    " complete. directIPs=" + DirectIpCount +
                    " resolvedIPs=" + ResolvedIpCount +
                    " totalIPs=" + TotalIpCount +
                    " resolveFile=" + ResolveFileName
                );
            }
            async Task WriteResolvedFileAsync(IEnumerable<IPAddress> addresses)
            {
                try
                {
                    string[] lines = addresses
                        .Select(NormalizeIp)
                        .Distinct()
                        .OrderBy(x => x.ToString(), StringComparer.OrdinalIgnoreCase)
                        .Select(x => x.ToString())
                        .ToArray();
                    await File.WriteAllLinesAsync(_resolvedPath, lines, Encoding.UTF8).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [ResolveWrite] Failed for " + ResolveFileName + ": " + ex.Message);
                }
            }
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
                            DnsDatagram aResp = await client.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN)).ConfigureAwait(false);
                            foreach (IPAddress a in DnsClient.ParseResponseA(aResp))
                            {
                                IPAddress normalized = NormalizeIp(a);
                                lock (results) { results.Add(normalized); }
                                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] " + host + " -> " + normalized);
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
                            int resolveTimeoutMs = Math.Max(5000, _httpTimeoutSeconds * 1000);
                            DnsDatagram aResp = await _dnsServer.DirectQueryAsync(
                                new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN),
                                resolveTimeoutMs
                            ).ConfigureAwait(false);
                            foreach (IPAddress a in DnsClient.ParseResponseA(aResp))
                            {
                                IPAddress normalized = NormalizeIp(a);
                                lock (results) { results.Add(normalized); }
                                _dnsServer.WriteLog("AdvancedBlockingWithUrlList: [Resolve] " + host + " -> " + normalized);
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
                IPAddress normalized = NormalizeIp(ip);
                lock (_lock)
                {
                    return _directIps.Contains(normalized) || _resolvedIps.Contains(normalized);
                }
            }
            static IPAddress NormalizeIp(IPAddress ip)
            {
                if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv4MappedToIPv6)
                    return ip.MapToIPv4();
                return ip;
            }
        }
    }
    static class JsonElementExtensions
    {
        public static bool GetPropertyValue(this JsonElement element, string propertyName, bool defaultValue)
        {
            if (element.TryGetProperty(propertyName, out JsonElement value) &&
                (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
                return value.GetBoolean();
            return defaultValue;
        }
        public static int GetPropertyValue(this JsonElement element, string propertyName, int defaultValue)
        {
            if (element.TryGetProperty(propertyName, out JsonElement value) &&
                value.ValueKind == JsonValueKind.Number &&
                value.TryGetInt32(out int intValue))
                return intValue;
            return defaultValue;
        }
        public static uint GetPropertyValue(this JsonElement element, string propertyName, uint defaultValue)
        {
            if (element.TryGetProperty(propertyName, out JsonElement value) &&
                value.ValueKind == JsonValueKind.Number &&
                value.TryGetUInt32(out uint uintValue))
                return uintValue;
            return defaultValue;
        }
    }
}
