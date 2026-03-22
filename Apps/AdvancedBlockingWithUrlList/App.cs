/*
 AdvancedBlockingWithUrlList - TestVersion1001
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
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
namespace AdvancedBlockingWithUrlList {
    public sealed class App : IDnsApplication, IDnsRequestBlockingHandler, IDisposable {
        private static readonly HttpClient s_httpClient = new HttpClient();
        private IDnsServer? _dnsServer;
        private uint _blockingAnswerTtl = 30;
        private int _downloadIntervalMinutes = 5;
        private int _downloadSleepSeconds = 30;
        private int _resolveIntervalSeconds = 300;
        private int _httpTimeoutSeconds = 30;
        private IPAddress[]? _resolveDnsServers;
        private DefaultBlockSettings _defaultBlock = DefaultBlockSettings.CreateDefault();
        private readonly Dictionary<string, IpList> _ipListsByName = new Dictionary<string, IpList>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, AllowList> _allowListsByUrl = new Dictionary<string, AllowList>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, RegexAllowList> _regexAllowListsByUrl = new Dictionary<string, RegexAllowList>(StringComparer.OrdinalIgnoreCase);
        private readonly List<Group> _groups = new List<Group>();
        private CancellationTokenSource? _cts;
        private Task? _downloadLoopTask;
        private Task? _resolveLoopTask;
        public string Description => "AdvancedBlockingWithUrlList: ordered allow rules per group, with global default block for matched clients.";
        public void Dispose() {
            StopWorkers();
        }
        public async Task InitializeAsync(IDnsServer dnsServer, string config) {
            _dnsServer = dnsServer;
            StopWorkers();
            ResetState();
            string normalizedConfig = NormalizeConfig(config);
            using JsonDocument doc = JsonDocument.Parse(normalizedConfig, new JsonDocumentOptions {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip
            });
            JsonElement root = doc.RootElement;
            _blockingAnswerTtl = root.GetPropertyValue("blockingAnswerTtl", 30u);
            _downloadIntervalMinutes = Math.Max(1, root.GetPropertyValue("blockListUrlUpdateIntervalMinutes", 5));
            _downloadSleepSeconds = Math.Max(0, root.GetPropertyValue("blockListUrlUpdateSleepSeconds", 30));
            _httpTimeoutSeconds = Math.Max(5, root.GetPropertyValue("httpTimeoutSeconds", 30));
            _resolveIntervalSeconds = Math.Max(300, root.GetPropertyValue("ipListResolveIntervalSeconds", 300));
            _resolveDnsServers = ParseDnsServers(root, "ipListResolveDnsServers");
            _defaultBlock = DefaultBlockSettings.FromJson(root.TryGetProperty("defaultBlock", out JsonElement defaultBlock) ? defaultBlock : default, dnsServer);
            LoadIpLists(root);
            LoadGroups(root);
            LinkSharedAllowLists();
            await InitialLoadAsync().ConfigureAwait(false);
            _cts = new CancellationTokenSource();
            _downloadLoopTask = Task.Run(() => DownloadLoopAsync(_cts.Token));
            _resolveLoopTask = Task.Run(() => ResolveLoopAsync(_cts.Token));
            Log("Initialized. groups=" + _groups.Count + ", ipLists=" + _ipListsByName.Count + ", allowLists=" + _allowListsByUrl.Count + ", regexAllowLists=" + _regexAllowListsByUrl.Count);
        }
        public Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP) {
            EvaluationResult result = EvaluateRequest(request, remoteEP, out _, out _);
            return Task.FromResult(result == EvaluationResult.Allow);
        }
        public Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP) {
            EvaluationResult result = EvaluateRequest(request, remoteEP, out Group? group, out string? report);
            if (result != EvaluationResult.Block)
                return Task.FromResult<DnsDatagram?>(null);
            return Task.FromResult<DnsDatagram?>(CreateBlockedResponse(request, group, report));
        }
        private void ResetState() {
            _ipListsByName.Clear();
            _allowListsByUrl.Clear();
            _regexAllowListsByUrl.Clear();
            _groups.Clear();
        }
        private void StopWorkers() {
            try {
                _cts?.Cancel();
                if (_downloadLoopTask is not null) {
                    try { _downloadLoopTask.Wait(TimeSpan.FromSeconds(5)); } catch { }
                    _downloadLoopTask = null;
                }
                if (_resolveLoopTask is not null) {
                    try { _resolveLoopTask.Wait(TimeSpan.FromSeconds(5)); } catch { }
                    _resolveLoopTask = null;
                }
            }
            finally {
                _cts?.Dispose();
                _cts = null;
            }
        }
        private void LoadIpLists(JsonElement root) {
            if (!root.TryGetProperty("ipListMaps", out JsonElement maps) || maps.ValueKind != JsonValueKind.Object)
                return;
            foreach (JsonProperty property in maps.EnumerateObject()) {
                string urlText = property.Name.Trim();
                string logicalName = (property.Value.GetString() ?? string.Empty).Trim();
                if (urlText.Length == 0 || logicalName.Length == 0)
                    continue;
                if (!Uri.TryCreate(urlText, UriKind.Absolute, out Uri? uri)) {
                    Log("Skipping invalid ipListMaps URL: " + urlText);
                    continue;
                }
                if (_ipListsByName.ContainsKey(logicalName)) {
                    Log("Duplicate logical IP list name ignored: " + logicalName);
                    continue;
                }
                _ipListsByName.Add(logicalName, new IpList(_dnsServer!, uri, logicalName, _httpTimeoutSeconds, _resolveDnsServers));
            }
        }
        private void LoadGroups(JsonElement root) {
            if (!root.TryGetProperty("groups", out JsonElement groups) || groups.ValueKind != JsonValueKind.Array)
                return;
            foreach (JsonElement item in groups.EnumerateArray()) {
                Group group = new Group(item);
                if (_ipListsByName.TryGetValue(group.Name, out IpList? ipList))
                    group.AttachIpList(ipList);
                else
                    Log("Group '" + group.Name + "' has no auto-linked IP list with the same name.");
                _groups.Add(group);
            }
        }
        private void LinkSharedAllowLists() {
            foreach (Group group in _groups) {
                foreach (Uri url in group.AllowListUrls) {
                    if (!_allowListsByUrl.TryGetValue(url.AbsoluteUri, out AllowList? list)) {
                        list = new AllowList(_dnsServer!, url, _httpTimeoutSeconds);
                        _allowListsByUrl.Add(url.AbsoluteUri, list);
                    }
                    group.AttachAllowList(list);
                }
                foreach (Uri url in group.RegexAllowListUrls) {
                    if (!_regexAllowListsByUrl.TryGetValue(url.AbsoluteUri, out RegexAllowList? list)) {
                        list = new RegexAllowList(_dnsServer!, url, _httpTimeoutSeconds);
                        _regexAllowListsByUrl.Add(url.AbsoluteUri, list);
                    }
                    group.AttachRegexAllowList(list);
                }
            }
        }
        private async Task InitialLoadAsync() {
            foreach (IpList ipList in _ipListsByName.Values) {
                try {
                    bool changed = await ipList.DownloadAndParseAsync().ConfigureAwait(false);
                    if (!changed)
                        ipList.ParseCachedPrimaryIfNeeded();
                    ipList.LoadResolvedCacheIfPresent();
                    await ipList.ResolveHostnamesAsync().ConfigureAwait(false);
                }
                catch (Exception ex) {
                    Log("Initial IP list load failed for '" + ipList.LogicalName + "': " + ex.Message);
                }
            }
            foreach (AllowList allowList in _allowListsByUrl.Values) {
                try {
                    bool changed = await allowList.DownloadAndParseAsync().ConfigureAwait(false);
                    if (!changed)
                        allowList.ParseCachedIfNeeded();
                }
                catch (Exception ex) {
                    Log("Initial allow list load failed for '" + allowList.ListUrl.AbsoluteUri + "': " + ex.Message);
                }
            }
            foreach (RegexAllowList regexList in _regexAllowListsByUrl.Values) {
                try {
                    bool changed = await regexList.DownloadAndParseAsync().ConfigureAwait(false);
                    if (!changed)
                        regexList.ParseCachedIfNeeded();
                }
                catch (Exception ex) {
                    Log("Initial regex allow list load failed for '" + regexList.ListUrl.AbsoluteUri + "': " + ex.Message);
                }
            }
        }
        private async Task DownloadLoopAsync(CancellationToken cancellationToken) {
            try {
                while (!cancellationToken.IsCancellationRequested) {
                    await Task.Delay(TimeSpan.FromMinutes(_downloadIntervalMinutes), cancellationToken).ConfigureAwait(false);
                    await DownloadAllListsAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) {
            }
            catch (Exception ex) {
                Log("Download loop failed: " + ex.Message);
            }
        }
        private async Task ResolveLoopAsync(CancellationToken cancellationToken) {
            try {
                while (!cancellationToken.IsCancellationRequested) {
                    await Task.Delay(TimeSpan.FromSeconds(_resolveIntervalSeconds), cancellationToken).ConfigureAwait(false);
                    foreach (IpList ipList in _ipListsByName.Values) {
                        cancellationToken.ThrowIfCancellationRequested();
                        try {
                            await ipList.ResolveHostnamesAsync().ConfigureAwait(false);
                        }
                        catch (Exception ex) {
                            Log("Resolve loop failed for '" + ipList.LogicalName + "': " + ex.Message);
                        }
                    }
                }
            }
            catch (OperationCanceledException) {
            }
            catch (Exception ex) {
                Log("Resolve loop failed: " + ex.Message);
            }
        }
        private async Task DownloadAllListsAsync(CancellationToken cancellationToken) {
            int index = 0;
            foreach (IpList ipList in _ipListsByName.Values) {
                cancellationToken.ThrowIfCancellationRequested();
                if (index > 0 && _downloadSleepSeconds > 0)
                    await Task.Delay(TimeSpan.FromSeconds(_downloadSleepSeconds), cancellationToken).ConfigureAwait(false);
                try {
                    bool changed = await ipList.DownloadAndParseAsync().ConfigureAwait(false);
                    if (changed)
                        await ipList.ResolveHostnamesAsync().ConfigureAwait(false);
                }
                catch (Exception ex) {
                    Log("IP list download failed for '" + ipList.LogicalName + "': " + ex.Message);
                }
                index++;
            }
            foreach (AllowList allowList in _allowListsByUrl.Values) {
                cancellationToken.ThrowIfCancellationRequested();
                if (index > 0 && _downloadSleepSeconds > 0)
                    await Task.Delay(TimeSpan.FromSeconds(_downloadSleepSeconds), cancellationToken).ConfigureAwait(false);
                try {
                    await allowList.DownloadAndParseAsync().ConfigureAwait(false);
                }
                catch (Exception ex) {
                    Log("Allow list download failed for '" + allowList.ListUrl.AbsoluteUri + "': " + ex.Message);
                }
                index++;
            }
            foreach (RegexAllowList regexList in _regexAllowListsByUrl.Values) {
                cancellationToken.ThrowIfCancellationRequested();
                if (index > 0 && _downloadSleepSeconds > 0)
                    await Task.Delay(TimeSpan.FromSeconds(_downloadSleepSeconds), cancellationToken).ConfigureAwait(false);
                try {
                    await regexList.DownloadAndParseAsync().ConfigureAwait(false);
                }
                catch (Exception ex) {
                    Log("Regex allow list download failed for '" + regexList.ListUrl.AbsoluteUri + "': " + ex.Message);
                }
                index++;
            }
        }
        private EvaluationResult EvaluateRequest(DnsDatagram request, IPEndPoint remoteEP, out Group? blockingGroup, out string? blockingReport) {
            blockingGroup = null;
            blockingReport = null;
            if (request is null || request.Question is null || request.Question.Count == 0)
                return EvaluationResult.None;
            IPAddress clientIp = NormalizeAddress(remoteEP.Address);
            string domain = NormalizeDomain(request.Question[0].Name);
            List<string> matchedGroupNames = new List<string>();
            foreach (Group group in _groups) {
                try {
                    if (!group.IsClientMatch(clientIp))
                        continue;
                    matchedGroupNames.Add(group.Name);
                    if (group.IsAllowed(domain, out string? allowSource)) {
                        Log("ALLOW group='" + group.Name + "' client='" + clientIp + "' domain='" + domain + "' source='" + allowSource + "'");
                        return EvaluationResult.Allow;
                    }
                }
                catch (Exception ex) {
                    Log("Evaluation failed in group '" + group.Name + "': " + ex.Message);
                }
            }
            if (matchedGroupNames.Count == 0)
                return EvaluationResult.None;
            blockingGroup = FindFirstMatchedGroup(clientIp);
            blockingReport = "source=advanced-blocking-with-url-list; action=default-block; client=" + clientIp + "; domain=" + domain + "; groups=" + string.Join(",", matchedGroupNames);
            Log("BLOCK client='" + clientIp + "' domain='" + domain + "' groups='" + string.Join(",", matchedGroupNames) + "'");
            return EvaluationResult.Block;
        }
        private Group? FindFirstMatchedGroup(IPAddress clientIp) {
            foreach (Group group in _groups) {
                if (group.IsClientMatch(clientIp))
                    return group;
            }
            return null;
        }
        private DnsDatagram CreateBlockedResponse(DnsDatagram request, Group? group, string? blockingReport) {
            DnsQuestionRecord question = request.Question[0];
            if (_defaultBlock.AllowTxtBlockingReport && question.Type == DnsResourceRecordType.TXT) {
                string txt = blockingReport ?? "source=advanced-blocking-with-url-list; action=default-block";
                DnsResourceRecord[] txtAnswer = new DnsResourceRecord[] {
                    new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _blockingAnswerTtl, new DnsTXTRecordData(txt))
                };
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, txtAnswer);
            }
            if (_defaultBlock.BlockAsNxDomain) {
                string parentDomain = GetParentZone(question.Name) ?? string.Empty;
                IReadOnlyList<DnsResourceRecord> authority = new DnsResourceRecord[] {
                    new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _defaultBlock.SoaRecord)
                };
                return new DnsDatagram(
                    request.Identifier,
                    true,
                    DnsOpcode.StandardQuery,
                    false,
                    false,
                    request.RecursionDesired,
                    false,
                    false,
                    false,
                    DnsResponseCode.NxDomain,
                    request.Question,
                    null,
                    authority,
                    null,
                    request.EDNS is null ? ushort.MinValue : _dnsServer!.UdpPayloadSize,
                    EDnsHeaderFlags.None,
                    null);
            }
            IReadOnlyList<DnsResourceRecord>? answer = null;
            IReadOnlyList<DnsResourceRecord>? authorityNoError = null;
            switch (question.Type) {
                case DnsResourceRecordType.A: {
                    if (_defaultBlock.ARecords.Count > 0) {
                        List<DnsResourceRecord> records = new List<DnsResourceRecord>(_defaultBlock.ARecords.Count);
                        foreach (DnsARecordData record in _defaultBlock.ARecords)
                            records.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _blockingAnswerTtl, record));
                        answer = records;
                    }
                    else {
                        authorityNoError = new DnsResourceRecord[] {
                            new DnsResourceRecord(question.Name, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _defaultBlock.SoaRecord)
                        };
                    }
                    break;
                }
                case DnsResourceRecordType.AAAA: {
                    if (_defaultBlock.AAAARecords.Count > 0) {
                        List<DnsResourceRecord> records = new List<DnsResourceRecord>(_defaultBlock.AAAARecords.Count);
                        foreach (DnsAAAARecordData record in _defaultBlock.AAAARecords)
                            records.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _blockingAnswerTtl, record));
                        answer = records;
                    }
                    else {
                        authorityNoError = new DnsResourceRecord[] {
                            new DnsResourceRecord(question.Name, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _defaultBlock.SoaRecord)
                        };
                    }
                    break;
                }
                case DnsResourceRecordType.NS:
                    answer = new DnsResourceRecord[] {
                        new DnsResourceRecord(question.Name, DnsResourceRecordType.NS, question.Class, _blockingAnswerTtl, _defaultBlock.NsRecord)
                    };
                    break;
                case DnsResourceRecordType.SOA:
                    answer = new DnsResourceRecord[] {
                        new DnsResourceRecord(question.Name, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _defaultBlock.SoaRecord)
                    };
                    break;
                default:
                    authorityNoError = new DnsResourceRecord[] {
                        new DnsResourceRecord(question.Name, DnsResourceRecordType.SOA, question.Class, _blockingAnswerTtl, _defaultBlock.SoaRecord)
                    };
                    break;
            }
            return new DnsDatagram(
                request.Identifier,
                true,
                DnsOpcode.StandardQuery,
                false,
                false,
                request.RecursionDesired,
                false,
                false,
                false,
                DnsResponseCode.NoError,
                request.Question,
                answer,
                authorityNoError,
                null,
                request.EDNS is null ? ushort.MinValue : _dnsServer!.UdpPayloadSize,
                EDnsHeaderFlags.None,
                null);
        }
        private static IPAddress[]? ParseDnsServers(JsonElement element, string propertyName) {
            if (!element.TryGetProperty(propertyName, out JsonElement servers) || servers.ValueKind != JsonValueKind.Array)
                return null;
            List<IPAddress> result = new List<IPAddress>();
            foreach (JsonElement item in servers.EnumerateArray()) {
                string? text = item.GetString();
                if (IPAddress.TryParse(text, out IPAddress? address))
                    result.Add(address);
            }
            return result.Count == 0 ? null : result.ToArray();
        }
        private static string NormalizeConfig(string config) {
            if (string.IsNullOrWhiteSpace(config))
                return "{}";
            string input = config.Replace("\r\n", "\n").Replace('\r', '\n');
            StringBuilder sb = new StringBuilder(input.Length);
            using StringReader reader = new StringReader(input);
            string? line;
            while ((line = reader.ReadLine()) is not null) {
                string trimmed = line.TrimStart();
                if (trimmed.StartsWith("##", StringComparison.Ordinal) || trimmed.StartsWith("#", StringComparison.Ordinal))
                    continue;
                sb.AppendLine(line);
            }
            return sb.ToString();
        }
        private static string NormalizeDomain(string domain) {
            return (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        }
        private static IPAddress NormalizeAddress(IPAddress address) {
            if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
                return address.MapToIPv4();
            return address;
        }
        private static string? GetParentZone(string domain) {
            string normalized = NormalizeDomain(domain);
            int index = normalized.IndexOf('.');
            if (index < 0 || index == normalized.Length - 1)
                return null;
            return normalized.Substring(index + 1);
        }
        private void Log(string message) {
            try { _dnsServer?.WriteLog("AdvancedBlockingWithUrlList: " + message); } catch { }
        }
        private enum EvaluationResult {
            None,
            Allow,
            Block
        }
        private sealed class Group {
            private readonly List<string> _allowedPatterns = new List<string>();
            private readonly List<Regex> _allowedRegex = new List<Regex>();
            private readonly List<AllowList> _allowLists = new List<AllowList>();
            private readonly List<RegexAllowList> _regexAllowLists = new List<RegexAllowList>();
            private IpList? _ipList;
            public string Name { get; }
            public IReadOnlyList<Uri> AllowListUrls { get; }
            public IReadOnlyList<Uri> RegexAllowListUrls { get; }
            public Group(JsonElement json) {
                Name = (json.GetProperty("name").GetString() ?? string.Empty).Trim();
                if (Name.Length == 0)
                    Name = "default";
                if (json.TryGetProperty("allowed", out JsonElement allowed) && allowed.ValueKind == JsonValueKind.Array) {
                    foreach (JsonElement item in allowed.EnumerateArray()) {
                        string normalized = NormalizeDomain(item.GetString() ?? string.Empty);
                        if (normalized.Length > 0)
                            _allowedPatterns.Add(normalized);
                    }
                }
                if (json.TryGetProperty("allowedRegex", out JsonElement allowedRegex) && allowedRegex.ValueKind == JsonValueKind.Array) {
                    foreach (JsonElement item in allowedRegex.EnumerateArray()) {
                        string pattern = (item.GetString() ?? string.Empty).Trim();
                        if (pattern.Length == 0)
                            continue;
                        _allowedRegex.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled));
                    }
                }
                AllowListUrls = ParseUriArray(json, "allowListUrls");
                RegexAllowListUrls = ParseUriArray(json, "regexAllowListUrls");
            }
            public void AttachIpList(IpList ipList) {
                _ipList = ipList;
            }
            public void AttachAllowList(AllowList allowList) {
                _allowLists.Add(allowList);
            }
            public void AttachRegexAllowList(RegexAllowList regexAllowList) {
                _regexAllowLists.Add(regexAllowList);
            }
            public bool IsClientMatch(IPAddress clientIp) {
                return _ipList is not null && _ipList.Contains(clientIp);
            }
            public bool IsAllowed(string domain, out string? source) {
                string normalized = NormalizeDomain(domain);
                foreach (string pattern in _allowedPatterns) {
                    if (DomainPatternMatcher.IsMatch(pattern, normalized)) {
                        source = "allowed:" + pattern;
                        return true;
                    }
                }
                foreach (AllowList list in _allowLists) {
                    if (list.IsMatch(normalized, out string? matchedPattern)) {
                        source = "allowListUrl:" + list.ListUrl.AbsoluteUri + ":" + matchedPattern;
                        return true;
                    }
                }
                foreach (Regex regex in _allowedRegex) {
                    if (regex.IsMatch(normalized)) {
                        source = "allowedRegex:" + regex.ToString();
                        return true;
                    }
                }
                foreach (RegexAllowList list in _regexAllowLists) {
                    if (list.IsMatch(normalized, out string? matchedRegex)) {
                        source = "regexAllowListUrl:" + list.ListUrl.AbsoluteUri + ":" + matchedRegex;
                        return true;
                    }
                }
                source = null;
                return false;
            }
            private static Uri[] ParseUriArray(JsonElement json, string propertyName) {
                if (!json.TryGetProperty(propertyName, out JsonElement array) || array.ValueKind != JsonValueKind.Array)
                    return Array.Empty<Uri>();
                List<Uri> uris = new List<Uri>();
                foreach (JsonElement item in array.EnumerateArray()) {
                    string? text = item.GetString();
                    if (Uri.TryCreate(text, UriKind.Absolute, out Uri? uri))
                        uris.Add(uri);
                }
                return uris.ToArray();
            }
        }
        private abstract class DownloadableListBase {
            protected readonly IDnsServer _dnsServer;
            private readonly string _cachePath;
            private readonly int _httpTimeoutSeconds;
            protected DownloadableListBase(IDnsServer dnsServer, Uri listUrl, string cacheFileName, int httpTimeoutSeconds) {
                _dnsServer = dnsServer;
                ListUrl = listUrl;
                _httpTimeoutSeconds = httpTimeoutSeconds;
                string folder = Path.Combine(_dnsServer.ApplicationFolder, "lists");
                Directory.CreateDirectory(folder);
                _cachePath = Path.Combine(folder, cacheFileName);
            }
            public Uri ListUrl { get; }
            protected string CachePath { get { return _cachePath; } }
            public async Task<bool> DownloadAndParseAsync() {
                bool changed = await DownloadAsync().ConfigureAwait(false);
                if (changed)
                    ParseCore();
                return changed;
            }
            protected IEnumerable<string> ReadLines(string path) {
                if (!File.Exists(path))
                    yield break;
                using StreamReader reader = new StreamReader(path, Encoding.UTF8);
                string? line;
                while ((line = reader.ReadLine()) is not null) {
                    string cleaned = line.Trim();
                    if (cleaned.Length == 0)
                        continue;
                    if (cleaned.StartsWith("#", StringComparison.Ordinal) || cleaned.StartsWith("!", StringComparison.Ordinal))
                        continue;
                    yield return cleaned;
                }
            }
            protected virtual async Task<bool> DownloadAsync() {
                using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, ListUrl);
                using CancellationTokenSource timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(_httpTimeoutSeconds));
                using HttpResponseMessage response = await s_httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: download HTTP " + (int)response.StatusCode + " for " + ListUrl.AbsoluteUri);
                    return false;
                }
                string newContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                string oldContent = File.Exists(_cachePath) ? await File.ReadAllTextAsync(_cachePath).ConfigureAwait(false) : string.Empty;
                if (string.Equals(oldContent, newContent, StringComparison.Ordinal))
                    return false;
                await File.WriteAllTextAsync(_cachePath, newContent, Encoding.UTF8).ConfigureAwait(false);
                return true;
            }
            protected abstract void ParseCore();
        }
        private sealed class IpList : DownloadableListBase {
            private const int ResolveBatchSize = 10;
            private readonly IPAddress[]? _resolveDnsServers;
            private readonly int _httpTimeoutSeconds;
            private readonly string _resolvePath;
            private readonly object _syncRoot = new object();
            private HashSet<IPAddress> _directIps = new HashSet<IPAddress>();
            private HashSet<string> _hostnames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            private HashSet<IPAddress> _resolvedIps = new HashSet<IPAddress>();
            public IpList(IDnsServer dnsServer, Uri listUrl, string logicalName, int httpTimeoutSeconds, IPAddress[]? resolveDnsServers)
                : base(dnsServer, listUrl, logicalName, httpTimeoutSeconds) {
                LogicalName = logicalName;
                _httpTimeoutSeconds = httpTimeoutSeconds;
                _resolveDnsServers = resolveDnsServers;
                _resolvePath = Path.Combine(dnsServer.ApplicationFolder, "lists", logicalName + "_Resolve");
            }
            public string LogicalName { get; }
            public void ParseCachedPrimaryIfNeeded() {
                lock (_syncRoot) {
                    if (_directIps.Count > 0 || _hostnames.Count > 0)
                        return;
                }
                ParseCore();
            }
            public void LoadResolvedCacheIfPresent() {
                HashSet<IPAddress> resolved = new HashSet<IPAddress>();
                foreach (string line in ReadLines(_resolvePath)) {
                    if (IPAddress.TryParse(line, out IPAddress? ip))
                        resolved.Add(NormalizeAddress(ip));
                }
                lock (_syncRoot) {
                    foreach (IPAddress direct in _directIps)
                        resolved.Remove(direct);
                    _resolvedIps = resolved;
                }
            }
            protected override void ParseCore() {
                HashSet<IPAddress> directIps = new HashSet<IPAddress>();
                HashSet<string> hostnames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (string line in ReadLines(CachePath)) {
                    if (IPAddress.TryParse(line, out IPAddress? ip)) {
                        directIps.Add(NormalizeAddress(ip));
                    }
                    else {
                        string host = NormalizeDomain(line);
                        if (host.Length > 0)
                            hostnames.Add(host);
                    }
                }
                lock (_syncRoot) {
                    _directIps = directIps;
                    _hostnames = hostnames;
                    _resolvedIps = new HashSet<IPAddress>();
                }
            }
            public async Task ResolveHostnamesAsync() {
                string[] hosts;
                HashSet<IPAddress> direct;
                lock (_syncRoot) {
                    hosts = new string[_hostnames.Count];
                    _hostnames.CopyTo(hosts);
                    direct = new HashSet<IPAddress>(_directIps);
                }
                HashSet<IPAddress> results = new HashSet<IPAddress>(direct);
                if (hosts.Length > 0) {
                    for (int offset = 0; offset < hosts.Length; offset += ResolveBatchSize) {
                        int count = Math.Min(ResolveBatchSize, hosts.Length - offset);
                        List<Task> batch = new List<Task>(count);
                        for (int i = 0; i < count; i++) {
                            string host = hosts[offset + i];
                            batch.Add(ResolveOneHostAsync(host, results));
                        }
                        try { await Task.WhenAll(batch).ConfigureAwait(false); } catch { }
                    }
                }
                HashSet<IPAddress> resolvedOnly = new HashSet<IPAddress>(results);
                foreach (IPAddress ip in direct)
                    resolvedOnly.Remove(ip);
                lock (_syncRoot) {
                    _resolvedIps = resolvedOnly;
                }
                WriteResolveFile(direct, resolvedOnly);
            }
            private async Task ResolveOneHostAsync(string host, HashSet<IPAddress> results) {
                try {
                    if (_resolveDnsServers is not null && _resolveDnsServers.Length > 0) {
                        DnsClient client = new DnsClient(_resolveDnsServers);
                        client.Proxy = _dnsServer.Proxy;
                        client.PreferIPv6 = false;
                        DnsDatagram response = await client.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN)).ConfigureAwait(false);
                        foreach (IPAddress ip in DnsClient.ParseResponseA(response)) {
                            lock (results)
                                results.Add(NormalizeAddress(ip));
                        }
                    }
                    else {
                        int timeoutMs = Math.Max(5000, _httpTimeoutSeconds * 1000);
                        DnsDatagram response = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), timeoutMs).ConfigureAwait(false);
                        foreach (IPAddress ip in DnsClient.ParseResponseA(response)) {
                            lock (results)
                                results.Add(NormalizeAddress(ip));
                        }
                    }
                }
                catch (Exception ex) {
                    _dnsServer.WriteLog("AdvancedBlockingWithUrlList: resolve failed for '" + host + "' from list '" + LogicalName + "': " + ex.Message);
                }
            }
            private void WriteResolveFile(HashSet<IPAddress> direct, HashSet<IPAddress> resolvedOnly) {
                List<string> lines = new List<string>(direct.Count + resolvedOnly.Count);
                foreach (IPAddress ip in direct)
                    lines.Add(ip.ToString());
                foreach (IPAddress ip in resolvedOnly)
                    lines.Add(ip.ToString());
                lines.Sort(StringComparer.OrdinalIgnoreCase);
                File.WriteAllLines(_resolvePath, lines, Encoding.UTF8);
            }
            public bool Contains(IPAddress clientIp) {
                IPAddress normalized = NormalizeAddress(clientIp);
                lock (_syncRoot) {
                    return _directIps.Contains(normalized) || _resolvedIps.Contains(normalized);
                }
            }
        }
        private sealed class AllowList : DownloadableListBase {
            private readonly HashSet<string> _patterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            private readonly object _syncRoot = new object();
            public AllowList(IDnsServer dnsServer, Uri listUrl, int httpTimeoutSeconds)
                : base(dnsServer, listUrl, MakeUrlCacheName(listUrl, ".allow"), httpTimeoutSeconds) {
            }
            public void ParseCachedIfNeeded() {
                lock (_syncRoot) {
                    if (_patterns.Count > 0)
                        return;
                }
                ParseCore();
            }
            protected override void ParseCore() {
                HashSet<string> patterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (string line in ReadLines(CachePath)) {
                    string normalized = NormalizeDomain(line);
                    if (normalized.Length > 0)
                        patterns.Add(normalized);
                }
                lock (_syncRoot) {
                    _patterns.Clear();
                    foreach (string pattern in patterns)
                        _patterns.Add(pattern);
                }
            }
            public bool IsMatch(string domain, out string? matchedPattern) {
                lock (_syncRoot) {
                    foreach (string pattern in _patterns) {
                        if (DomainPatternMatcher.IsMatch(pattern, domain)) {
                            matchedPattern = pattern;
                            return true;
                        }
                    }
                }
                matchedPattern = null;
                return false;
            }
        }
        private sealed class RegexAllowList : DownloadableListBase {
            private Regex[] _regex = Array.Empty<Regex>();
            private readonly object _syncRoot = new object();
            public RegexAllowList(IDnsServer dnsServer, Uri listUrl, int httpTimeoutSeconds)
                : base(dnsServer, listUrl, MakeUrlCacheName(listUrl, ".regex"), httpTimeoutSeconds) {
            }
            public void ParseCachedIfNeeded() {
                lock (_syncRoot) {
                    if (_regex.Length > 0)
                        return;
                }
                ParseCore();
            }
            protected override void ParseCore() {
                List<Regex> regex = new List<Regex>();
                foreach (string line in ReadLines(CachePath)) {
                    string pattern = line.Trim();
                    if (pattern.Length == 0)
                        continue;
                    try {
                        regex.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled));
                    }
                    catch {
                    }
                }
                lock (_syncRoot) {
                    _regex = regex.ToArray();
                }
            }
            public bool IsMatch(string domain, out string? matchedRegex) {
                lock (_syncRoot) {
                    foreach (Regex regex in _regex) {
                        if (regex.IsMatch(domain)) {
                            matchedRegex = regex.ToString();
                            return true;
                        }
                    }
                }
                matchedRegex = null;
                return false;
            }
        }
        private sealed class DefaultBlockSettings {
            private DefaultBlockSettings(bool allowTxtBlockingReport, bool blockAsNxDomain, List<DnsARecordData> aRecords, List<DnsAAAARecordData> aaaaRecords, DnsNSRecordData nsRecord, DnsSOARecordData soaRecord) {
                AllowTxtBlockingReport = allowTxtBlockingReport;
                BlockAsNxDomain = blockAsNxDomain;
                ARecords = aRecords;
                AAAARecords = aaaaRecords;
                NsRecord = nsRecord;
                SoaRecord = soaRecord;
            }
            public bool AllowTxtBlockingReport { get; }
            public bool BlockAsNxDomain { get; }
            public List<DnsARecordData> ARecords { get; }
            public List<DnsAAAARecordData> AAAARecords { get; }
            public DnsNSRecordData NsRecord { get; }
            public DnsSOARecordData SoaRecord { get; }
            public static DefaultBlockSettings CreateDefault() {
                string nsDomain = "blocked.local";
                DnsNSRecordData nsRecord = new DnsNSRecordData(nsDomain);
                DnsSOARecordData soaRecord = new DnsSOARecordData(nsDomain, "hostmaster." + nsDomain, 1, 3600, 600, 86400, 30);
                return new DefaultBlockSettings(false, false, new List<DnsARecordData> { new DnsARecordData(IPAddress.Loopback) }, new List<DnsAAAARecordData>(), nsRecord, soaRecord);
            }
            public static DefaultBlockSettings FromJson(JsonElement json, IDnsServer dnsServer) {
                bool allowTxtBlockingReport = json.ValueKind != JsonValueKind.Undefined && json.GetPropertyValue("allowTxtBlockingReport", false);
                bool blockAsNxDomain = json.ValueKind != JsonValueKind.Undefined && json.GetPropertyValue("blockAsNxDomain", false);
                List<DnsARecordData> aRecords = new List<DnsARecordData>();
                List<DnsAAAARecordData> aaaaRecords = new List<DnsAAAARecordData>();
                if (json.ValueKind != JsonValueKind.Undefined && json.TryGetProperty("blockingAddresses", out JsonElement blockingAddresses) && blockingAddresses.ValueKind == JsonValueKind.Array) {
                    foreach (JsonElement item in blockingAddresses.EnumerateArray()) {
                        if (!IPAddress.TryParse(item.GetString(), out IPAddress? address))
                            continue;
                        switch (address.AddressFamily) {
                            case AddressFamily.InterNetwork:
                                aRecords.Add(new DnsARecordData(address));
                                break;
                            case AddressFamily.InterNetworkV6:
                                aaaaRecords.Add(new DnsAAAARecordData(address));
                                break;
                        }
                    }
                }
                if (aRecords.Count == 0 && aaaaRecords.Count == 0 && !blockAsNxDomain)
                    aRecords.Add(new DnsARecordData(IPAddress.Loopback));
                string nsDomain = dnsServer.ServerDomain ?? "blocked.local";
                DnsNSRecordData nsRecord = new DnsNSRecordData(nsDomain);
                DnsSOARecordData soaRecord = new DnsSOARecordData(nsDomain, dnsServer.ResponsiblePerson.Address, 1, 3600, 600, 86400, 30);
                return new DefaultBlockSettings(allowTxtBlockingReport, blockAsNxDomain, aRecords, aaaaRecords, nsRecord, soaRecord);
            }
        }
        private static class DomainPatternMatcher {
            public static bool IsMatch(string pattern, string domain) {
                if (pattern.Length == 0 || domain.Length == 0)
                    return false;
                if (pattern == "*" || pattern == "*.*")
                    return true;
                if (pattern.StartsWith("*.", StringComparison.Ordinal)) {
                    string suffix = pattern.Substring(2);
                    return domain.Equals(suffix, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase);
                }
                return domain.Equals(pattern, StringComparison.OrdinalIgnoreCase);
            }
        }
        private static string MakeUrlCacheName(Uri uri, string suffix) {
            unchecked {
                string key = uri.AbsoluteUri.ToLowerInvariant();
                int hash = 17;
                foreach (char ch in key)
                    hash = hash * 31 + ch;
                return Math.Abs(hash).ToString() + suffix;
            }
        }
    }
    internal static class JsonElementExtensions {
        public static bool GetPropertyValue(this JsonElement element, string propertyName, bool defaultValue) {
            if (element.ValueKind != JsonValueKind.Undefined && element.TryGetProperty(propertyName, out JsonElement value) && (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
                return value.GetBoolean();
            return defaultValue;
        }
        public static int GetPropertyValue(this JsonElement element, string propertyName, int defaultValue) {
            if (element.ValueKind != JsonValueKind.Undefined && element.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int result))
                return result;
            return defaultValue;
        }
        public static uint GetPropertyValue(this JsonElement element, string propertyName, uint defaultValue) {
            if (element.ValueKind != JsonValueKind.Undefined && element.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.Number && value.TryGetUInt32(out uint result))
                return result;
            return defaultValue;
        }
    }
}
