VULNERABILITY MONITOR (VULMON) v3.3
API-Based Vulnerability Monitoring

══════════════════════════════════════════════════════════════════

DATA SOURCES & STATUS INDICATORS

The tool queries three official APIs and shows real-time status:

✓ Active      - API queried successfully, data retrieved
⚠ Limited     - Partial data or degraded service
✗ Error       - Query failed (check connectivity/rate limits)
Not Queried   - API not yet used in this session

PRIMARY SOURCE:
• NIST NVD (National Vulnerability Database)
  - Official US Government CVE database
  - Most comprehensive vulnerability data
  - All CVEs from all vendors
  - Website: https://nvd.nist.gov/
  
ENRICHMENT SOURCE:
• CIRCL CVE Search
  - Fast CVE detail lookup
  - Supplementary vulnerability information
  - Website: https://cve.circl.lu/
  - NOTE: Use the checkbox to enable this source. It is
    slower as it queries every CVE found.

OPTIONAL SOURCE:
• Microsoft MSRC (Security Response Center)
  - Official Microsoft security bulletins
  - Enhanced Windows/Office monitoring
  - Requires PowerShell module installation
  - Website: https://msrc.microsoft.com/

══════════════════════════════════════════════════════════════════

SOURCE COLUMN IN RESULTS

Each vulnerability shows which API provided the data:
• "NIST NVD" - Direct from National Vulnerability Database
• "MS MSRC" - From Microsoft Security Response Center

This transparency lets you verify data provenance.

══════════════════════════════════════════════════════════════════

QUICK START

1. Enter products to monitor (one per line)
2. Set the "Start Date" and "End Date"
3. Choose your filter method:
   • (Default) Leave "Critical" and "High" checked
   • -OR- Check "Show CISA Known Exploited (KEV) Only"
     for the most urgent, in-the-wild threats.
4. (Optional) Check "Enrich CVEs with CIRCL" for more
   detailed data (this is slower).
5. Click "Check Updates"
6. Watch source status indicators update in real-time
7. Review color-coded results:
   • RED = New critical/high vulnerabilities
   • PINK = Existing critical vulnerabilities
   • YELLOW = High severity
   • WHITE = Medium/low severity

══════════════════════════════════════════════════════════════════

SEARCH FILTERS EXPLAINED

• Critical / High: Filters by theoretical severity
  (CVSS score). This shows what *could* be bad.

• Show CISA KEV Only: Filters by real-world threat.
  Shows only vulnerabilities that CISA has confirmed
  are actively being used in attacks. This is the
  most urgent filter. When checked, it overrides
  the Critical/High filter and skips the MSRC query
  (as MSRC does not support KEV filtering).

══════════════════════════════════════════════════════════════════

NVD API KEY (OPTIONAL BUT RECOMMENDED)

Why get an API key?
• Increases rate limit from 5 to 50 requests per 30 seconds
• Completely free (5-minute signup)
• Faster searches when monitoring many products

How to get:
1. Click "Get a free NVD API key" link
2. Fill out simple form (name, email, org)
3. Receive key via email
4. Paste into "NVD API Key" field
5. Click "Save Key"

══════════════════════════════════════════════════════════════════

VERSION HISTORY

v3.4 (This version)
     - Added CISA KEV (Known Exploited) filter
     - Added "Start Date" / "End Date" range
     - Added Critical/High severity filters
     - Fixed MSRC module parameter errors
     - Fixed MSRC module install path (OneDrive)
v3.3 - Added optional CIRCL enrichment checkbox
     - Fixed UI layout for Data Sources box
     - Fixed product list loading line-ending bug
v3.2 - Enhanced API source display
     - Real-time status indicators
     - Source transparency in UI and results
v3.1 - Fixed UI layout, added import/export
v3.0 - Complete rewrite using official APIs
