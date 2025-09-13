// AuthHive.Auth/Services/Helpers/DnsVerificationHelper.cs
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Organization.Common;
using DnsClient;

namespace AuthHive.Auth.Services.Helpers
{
    /// <summary>
    /// DNS 검증 Helper 구현체 - AuthHive v15
    /// DnsClient.NET을 사용한 DNS 레코드 검증 구현
    /// </summary>
    public class DnsVerificationHelper : IDnsVerificationHelper
    {
        private readonly ILookupClient _lookupClient;
        private readonly ILogger<DnsVerificationHelper> _logger;
        
        // DNS 검증을 위한 표준 접두사
        private const string TXT_RECORD_PREFIX = "_authive-verification";
        private const string CNAME_RECORD_PREFIX = "_authive";

        public DnsVerificationHelper(
            ILookupClient lookupClient,
            ILogger<DnsVerificationHelper> logger)
        {
            _lookupClient = lookupClient ?? throw new ArgumentNullException(nameof(lookupClient));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<DnsVerificationResult> VerifyDnsRecordAsync(
            string domain, 
            string expectedValue, 
            string recordType)
        {
            try
            {
                var result = new DnsVerificationResult
                {
                    RecordType = recordType,
                    ExpectedValue = expectedValue,
                    QueriedAt = DateTime.UtcNow
                };

                string queryDomain = GetVerificationDomain(domain, recordType);
                
                switch (recordType.ToUpperInvariant())
                {
                    case "TXT":
                        result = await VerifyTxtRecordAsync(queryDomain, expectedValue);
                        break;
                        
                    case "CNAME":
                        result = await VerifyCnameRecordAsync(queryDomain, expectedValue);
                        break;
                        
                    default:
                        result.ErrorMessage = $"Unsupported record type: {recordType}";
                        break;
                }

                _logger.LogInformation(
                    "DNS verification for {Domain}: {Result}",
                    domain, result.IsMatch ? "Success" : "Failed");

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying DNS record for {Domain}", domain);
                
                return new DnsVerificationResult
                {
                    RecordType = recordType,
                    ExpectedValue = expectedValue,
                    RecordFound = false,
                    IsMatch = false,
                    ErrorMessage = ex.Message,
                    QueriedAt = DateTime.UtcNow
                };
            }
        }

        public async Task<DnsVerificationResult> CheckDnsRecordsAsync(string domain)
        {
            try
            {
                var result = new DnsVerificationResult
                {
                    RecordType = "Multiple",
                    QueriedAt = DateTime.UtcNow,
                    AdditionalRecords = new List<string>()
                };

                // A 레코드 확인
                var aRecords = await _lookupClient.QueryAsync(domain, QueryType.A);
                if (aRecords.Answers.ARecords().Any())
                {
                    var ips = aRecords.Answers.ARecords().Select(r => r.Address.ToString());
                    result.AdditionalRecords.Add($"A: {string.Join(", ", ips)}");
                }

                // CNAME 레코드 확인
                var cnameRecords = await _lookupClient.QueryAsync(domain, QueryType.CNAME);
                if (cnameRecords.Answers.CnameRecords().Any())
                {
                    var cnames = cnameRecords.Answers.CnameRecords().Select(r => r.CanonicalName.Value);
                    result.AdditionalRecords.Add($"CNAME: {string.Join(", ", cnames)}");
                }

                // MX 레코드 확인
                var mxRecords = await _lookupClient.QueryAsync(domain, QueryType.MX);
                if (mxRecords.Answers.MxRecords().Any())
                {
                    var mxs = mxRecords.Answers.MxRecords()
                        .OrderBy(r => r.Preference)
                        .Select(r => $"{r.Preference}:{r.Exchange}");
                    result.AdditionalRecords.Add($"MX: {string.Join(", ", mxs)}");
                }

                // TXT 레코드 확인
                var txtRecords = await _lookupClient.QueryAsync(domain, QueryType.TXT);
                if (txtRecords.Answers.TxtRecords().Any())
                {
                    var txts = txtRecords.Answers.TxtRecords()
                        .SelectMany(r => r.Text)
                        .Where(t => t.Contains("authive", StringComparison.OrdinalIgnoreCase));
                    if (txts.Any())
                    {
                        result.AdditionalRecords.Add($"TXT: {string.Join(", ", txts)}");
                    }
                }

                result.RecordFound = result.AdditionalRecords.Any();
                
                _logger.LogInformation(
                    "DNS check for {Domain} found {Count} records",
                    domain, result.AdditionalRecords.Count);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking DNS records for {Domain}", domain);
                
                return new DnsVerificationResult
                {
                    RecordType = "Multiple",
                    RecordFound = false,
                    ErrorMessage = ex.Message,
                    QueriedAt = DateTime.UtcNow
                };
            }
        }

        private async Task<DnsVerificationResult> VerifyTxtRecordAsync(string domain, string expectedValue)
        {
            var result = new DnsVerificationResult
            {
                RecordType = "TXT",
                ExpectedValue = expectedValue,
                QueriedAt = DateTime.UtcNow
            };

            try
            {
                var queryResult = await _lookupClient.QueryAsync(domain, QueryType.TXT);
                var txtRecords = queryResult.Answers.TxtRecords().ToList();

                if (txtRecords.Any())
                {
                    result.RecordFound = true;
                    
                    // 모든 TXT 레코드 확인
                    foreach (var record in txtRecords)
                    {
                        var recordValue = string.Join("", record.Text);
                        
                        if (recordValue.Equals(expectedValue, StringComparison.OrdinalIgnoreCase))
                        {
                            result.ActualValue = recordValue;
                            result.IsMatch = true;
                            result.Ttl = record.TimeToLive;
                            break;
                        }
                        
                        // 추가 레코드로 저장
                        result.AdditionalRecords.Add(recordValue);
                    }

                    if (!result.IsMatch && result.AdditionalRecords.Any())
                    {
                        result.ActualValue = result.AdditionalRecords.First();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying TXT record for {Domain}", domain);
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task<DnsVerificationResult> VerifyCnameRecordAsync(string domain, string expectedValue)
        {
            var result = new DnsVerificationResult
            {
                RecordType = "CNAME",
                ExpectedValue = expectedValue,
                QueriedAt = DateTime.UtcNow
            };

            try
            {
                var queryResult = await _lookupClient.QueryAsync(domain, QueryType.CNAME);
                var cnameRecords = queryResult.Answers.CnameRecords().ToList();

                if (cnameRecords.Any())
                {
                    result.RecordFound = true;
                    var actualCname = cnameRecords.First().CanonicalName.Value.TrimEnd('.');
                    result.ActualValue = actualCname;
                    
                    result.IsMatch = actualCname.Equals(
                        expectedValue.TrimEnd('.'), 
                        StringComparison.OrdinalIgnoreCase);
                    
                    result.Ttl = cnameRecords.First().TimeToLive;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying CNAME record for {Domain}", domain);
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private string GetVerificationDomain(string domain, string recordType)
        {
            switch (recordType.ToUpperInvariant())
            {
                case "TXT":
                    return $"{TXT_RECORD_PREFIX}.{domain}";
                case "CNAME":
                    return $"{CNAME_RECORD_PREFIX}.{domain}";
                default:
                    return domain;
            }
        }
    }
}