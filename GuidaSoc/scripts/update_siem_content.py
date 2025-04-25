#!/usr/bin/env python3
"""
Script per arricchire il contenuto delle sezioni SIEM con query e informazioni
dalle documentazioni ufficiali usando trafilatura per estrarre il contenuto.
"""

import os
import json
import trafilatura

# URL delle documentazioni ufficiali
DOCS_URLS = {
    "splunk": [
        "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search",
        "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchCheatsheet",
        "https://docs.splunk.com/Documentation/Splunk/latest/Security/UseSecurityCentertomonitorandanalyzesecuritydata"
    ],
    "elastic": [
        "https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html",
        "https://www.elastic.co/guide/en/security/current/detection-engine-overview.html",
        "https://www.elastic.co/guide/en/security/current/prebuilt-rules.html"
    ],
    "defender": [
        "https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview",
        "https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language",
        "https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables"
    ],
    "qradar": [
        "https://www.ibm.com/docs/en/qsip/7.4?topic=guide-aql-overview",
        "https://www.ibm.com/docs/en/qsip/7.4?topic=queries-aql-query-examples",
        "https://www.ibm.com/docs/en/qsip/7.4?topic=hunting-threat-use-cases"
    ],
    "sentinel": [
        "https://docs.microsoft.com/en-us/azure/sentinel/kusto-query-language",
        "https://docs.microsoft.com/en-us/azure/sentinel/hunting",
        "https://docs.microsoft.com/en-us/azure/sentinel/import-threat-intelligence"
    ]
}

# Query di esempio aggiuntive per ciascuna piattaforma
QUERY_EXAMPLES = {
    "splunk": [
        {
            "title": "Rilevamento di modifiche critiche alle policy di sistema",
            "description": "Questa query identifica modifiche alle policy di sicurezza di Windows, che potrebbero indicare tentativi di indebolire le difese del sistema.",
            "query": """index=windows EventCode=4739 OR EventCode=4738 OR EventCode=4670
| stats count by host, user, EventCode
| eval criticality=case(
    EventCode=4739, "High - Domain Policy Change",
    EventCode=4738, "Medium - User Account Change",
    EventCode=4670, "High - Permission/ACL Change")
| table _time, host, user, EventCode, criticality"""
        },
        {
            "title": "Individuazione di processi PowerShell sospetti",
            "description": "Ricerca comandi PowerShell che utilizzano tecniche comuni di evasione e offuscamento.",
            "query": """index=windows sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational
| search EventCode=4688 OR EventCode=4103 OR EventCode=4104
| regex CommandLine="(?i)(-enc|-encodedcommand|-e|\\-w\\s+hidden|bypass|downloadstring|invoke-expression|iex\\s|invoke-webrequest)"
| stats count min(_time) as firstTime max(_time) as lastTime by host, user, CommandLine
| sort - count"""
        },
        {
            "title": "Creazione di servizi Windows sospetti",
            "description": "Identifica la creazione di nuovi servizi Windows, spesso utilizzata come metodo di persistenza.",
            "query": """index=windows (EventCode=7045 OR (EventCode=4697 AND sourcetype=WinEventLog:Security))
| table _time, host, source, user, service_name, service_file_name
| rename "service_file_name" as binary_path
| search NOT [| inputlookup service_whitelist.csv | fields binary_path]"""
        }
    ],
    "elastic": [
        {
            "title": "Rilevamento di connessioni a domini di C2 noti",
            "description": "Identifica host interni che comunicano con domini noti come infrastrutture Command and Control.",
            "query": """
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.category": "network" } },
        { "term": { "event.type": "connection" } }
      ],
      "should": [
        { "term": { "destination.domain": "malicious-domain1.com" } },
        { "term": { "destination.domain": "malicious-domain2.com" } },
        { "match_phrase": { "destination.ip": "103.104.105.106" } }
      ],
      "minimum_should_match": 1,
      "filter": [
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ]
    }
  }
}"""
        },
        {
            "title": "Uso sospetto di WMI per esecuzione remota",
            "description": "Identifica l'uso di WMI per l'esecuzione remota di comandi, tecnica comune nei lateral movement.",
            "query": """
{
  "query": {
    "bool": {
      "must": [
        { "match_phrase": { "process.name": "wmic.exe" } },
        { "wildcard": { "process.command_line": "*process call create*" } }
      ],
      "filter": [
        { "range": { "@timestamp": { "gte": "now-12h" } } }
      ]
    }
  }
}"""
        },
        {
            "title": "Individuazione di script potenzialmente dannosi nelle cartelle temporanee",
            "description": "Rileva script e file eseguibili salvati nelle cartelle temp, spesso utilizzate da malware.",
            "query": """
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.category": "file" } },
        { "terms": { "event.type": ["creation", "change"] } }
      ],
      "filter": [
        { "wildcard": { "file.path": "*\\\\temp\\\\*.js" } },
        { "wildcard": { "file.path": "*\\\\temp\\\\*.vbs" } },
        { "wildcard": { "file.path": "*\\\\temp\\\\*.ps1" } },
        { "wildcard": { "file.path": "*\\\\temp\\\\*.exe" } }
      ],
      "should": [
        { "term": { "process.name": "powershell.exe" } },
        { "term": { "process.name": "cmd.exe" } },
        { "term": { "process.name": "wscript.exe" } },
        { "term": { "process.name": "cscript.exe" } }
      ],
      "minimum_should_match": 1
    }
  }
}"""
        }
    ],
    "defender": [
        {
            "title": "Creazioni di chiavi di registro per persistence",
            "description": "Identifica la creazione di chiavi di registro comunemente utilizzate per la persistenza del malware.",
            "query": """DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey matches regex @".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|.*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce|.*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx|.*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\StartupApproved"
| where PreviousRegistryValueData != RegistryValueData or isempty(PreviousRegistryValueData)
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc"""
        },
        {
            "title": "Download sospetti da domini di recente creazione",
            "description": "Rileva download di file eseguibili da domini creati negli ultimi 30 giorni, potenziale indicatore di campagne malware.",
            "query": """let newDomains = materialize (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl !startswith "10." and RemoteUrl !startswith "192.168." and RemoteUrl !startswith "172."
    | extend domain = tostring(parse_url(RemoteUrl).Host)
    | where isnotempty(domain)
    | summarize firstSeen = min(Timestamp) by domain
    | where firstSeen > ago(30d)
);
DeviceFileEvents
| where ActionType == "FileCreated" or ActionType == "FileModified"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1" or FileName endswith ".vbs"
| join kind=inner newDomains on $left.RequestUrl contains $right.domain
| project Timestamp, DeviceName, FileName, FolderPath, RequestUrl, domain, firstSeen, InitiatingProcessCommandLine
| order by Timestamp desc"""
        },
        {
            "title": "Command line evasion techniques",
            "description": "Cerca tecniche di evasione nella riga di comando di processi, come l'uso di parametri per nascondere finestre o bypassare restrizioni.",
            "query": """DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any("-w hidden", "-window hidden", "-enc", "-encodedcommand", "-nop", 
    "-noprofile", "bypass", "-decode", "frombase64string", "downloadstring", "downloadfile")
| extend CommandLineLower = tolower(ProcessCommandLine)
| extend EncodedCommand = extract(@"-e[ncodedCommand]* ([A-Za-z0-9+/]{20,}={0,2})", 1, CommandLineLower)
| extend CommandlineLength = strlen(ProcessCommandLine)
| project Timestamp, DeviceName, ProcessCommandLine, CommandlineLength, EncodedCommand, AccountName, AccountDomain, ProcessId, ParentProcessName, InitiatingProcessCommandLine
| sort by Timestamp desc"""
        }
    ],
    "qradar": [
        {
            "title": "Rilevazione di Access Token manipolati",
            "description": "Identifica potenziali manipolazioni di access token, una tecnica utilizzata per l'escalation dei privilegi.",
            "query": """SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') as time_stamp,
eventname, hostname, username, 
LOGSOURCENAME(devicetype) as source_type,
CATEGORYNAME(category) as category_name
FROM events 
WHERE (eventname ILIKE '%1878%' OR eventname ILIKE '%token%')
AND LOGSOURCENAME(devicetype) ILIKE '%windows%'
AND eventname NOT ILIKE '%logon%'
AND "identHostName" IS NOT NULL
AND QIDNAME(qid) ILIKE '%privilege%'
ORDER BY time_stamp DESC
LAST 7 DAYS"""
        },
        {
            "title": "Analisi connessioni DNS sospette",
            "description": "Cerca connessioni DNS anomale che potrebbero indicare data exfiltration o comunicazioni C2 basate su DNS.",
            "query": """SELECT sourceip, destinationip, LONG(eventcount) as eventcount,
MIN(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')) as first_time,
MAX(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')) as last_time,
SUM(LONG(destinationpayloadlength)) as total_bytes
FROM flows 
WHERE protocolid = '17' AND destinationport = '53'
AND (destinationpayloadlength > 200 OR sourcepackets > 15)
GROUP BY sourceip, destinationip
HAVING eventcount > 50
ORDER BY total_bytes DESC
LAST 48 HOURS"""
        },
        {
            "title": "Rilevazione Lateral Movement tramite account amministrativi",
            "description": "Identifica possibili movimenti laterali attraverso l'utilizzo di account amministrativi su più sistemi.",
            "query": """SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') as time_stamp,
sourceip, destinationip, username, 
COUNT(destinationip) OVER (PARTITION BY username, sourceip) as unique_destinations,
CATEGORYNAME(category) as category
FROM events 
WHERE "eventAction" = 'Administrator Logon'
AND sourceip IS NOT NULL
AND destinationip IS NOT NULL
AND username IS NOT NULL
GROUP BY time_stamp, sourceip, destinationip, username, category
HAVING unique_destinations > 3
ORDER BY time_stamp DESC
LAST 24 HOURS"""
        }
    ],
    "sentinel": [
        {
            "title": "Attività anomala di autenticazione",
            "description": "Rileva attività di autenticazione anomala per utenti, confrontando il comportamento recente con quello storico.",
            "query": """// Interroga per trovare attività anomale di login in base alla location dell'utente
let timeframe = 14d;
let lookBack = 7d;
let discoverableTimeframe = 14d;
// Crea un dataset degli utenti che hanno effettuato l'accesso con successo
let authenticatedUsers =
    SigninLogs
    | where TimeGenerated >= ago(timeframe)
    | where ResultType == 0
    | summarize by UserId, UserPrincipalName;
// Trova i primi accessi per regione geografica per utente
let firstTimeAccess =
    SigninLogs
    | where TimeGenerated >= ago(discoverableTimeframe)
    | where ResultType == 0
    | summarize FirstTimeSuccessfulAccess = min(TimeGenerated) by UserId, UserPrincipalName, Location, Country
    | summarize FirstTimeSuccessfulAccessPerCountry = make_list(pack('Country', Country, 'Time', FirstTimeSuccessfulAccess)) by UserId, UserPrincipalName;
// Monitora accessi recenti per identificare nuove località
let recentAccess =
    SigninLogs
    | where TimeGenerated >= ago(lookBack)
    | where ResultType == 0
    | summarize NumAccess = count(), LastSuccessfulAccess = max(TimeGenerated) by UserId, UserPrincipalName, Location, Country;
// Identifica accessi anomali
let anomalousAccess =
    recentAccess
    | join kind=inner (
        firstTimeAccess
    ) on UserId, UserPrincipalName
    | mv-expand FirstTimeSuccessfulAccessPerCountry
    | extend 
        Country1 = tostring(FirstTimeSuccessfulAccessPerCountry.Country),
        FirstTimeSuccessfulAccessTime = todatetime(FirstTimeSuccessfulAccessPerCountry.Time)
    | extend RecentLoginDiff = LastSuccessfulAccess - FirstTimeSuccessfulAccessTime
    | where RecentLoginDiff <= lookBack
    | where Country != Country1 // Accesso avvenuto da un paese diverso dal solito
    | project UserPrincipalName, LastSuccessfulAccess, Country, NumAccess, FirstTimeSuccessfulAccessTime, Country1, RecentLoginDiff
    | summarize NumNewCountries = count(), Countries = make_list(Country) by UserPrincipalName
    | where NumNewCountries >= 2; // L'utente ha effettuato l'accesso da almeno 2 nuovi paesi
// Output finale
authenticatedUsers
| join kind=inner anomalousAccess on UserPrincipalName
| project UserPrincipalName, NumNewCountries, Countries"""
        },
        {
            "title": "Rilevamento Kerberoasting",
            "description": "Identifica potenziali attacchi Kerberoasting, una tecnica utilizzata per ottenere credenziali di account di servizio.",
            "query": """SecurityEvent
| where EventID == 4769
| where ServiceName != "krbtgt"
| where ServiceName !contains "$"
| where ServiceName !contains "@"
| extend encryption_type = iff(TicketEncryptionType == '0x1', 'DES-CBC-CRC',
                             iff(TicketEncryptionType == '0x3', 'DES-CBC-MD5',
                             iff(TicketEncryptionType == '0x11', 'AES128-CTS-HMAC-SHA1-96',
                             iff(TicketEncryptionType == '0x12', 'AES256-CTS-HMAC-SHA1-96',
                             iff(TicketEncryptionType == '0x17', 'RC4-HMAC',
                             iff(TicketEncryptionType == '0x18', 'RC4-HMAC-EXP',
                                 'UNKNOWN'))))))
| where encryption_type == "RC4-HMAC" // RC4 è più vulnerabile
| summarize count() by TargetUserName, TargetDomainName, ClientIPAddress, Account, Computer, encryption_type
| extend attack_potential = iff(count_ > 10, 'High', iff(count_ > 5, 'Medium', 'Low'))
| order by count_ desc"""
        },
        {
            "title": "Rilevamento di accesso a dati sensibili",
            "description": "Identifica l'accesso a documenti e dati classificati come sensibili in Office 365.",
            "query": """// Monitora l'accesso a file sensibili in Office 365 
let timeRange = 30d;
let sensitiveLabels = dynamic(["Confidential", "Restricted", "Internal Only", "Highly Confidential"]);
OfficeActivity
| where TimeGenerated > ago(timeRange)
| where RecordType in ("SharePointFileOperation", "OneDriveFileOperation")
| where Operation in ("FileAccessed", "FileDownloaded", "FilePreviewed")
| join kind=leftouter (
    OfficeActivity
    | where TimeGenerated > ago(timeRange)
    | where RecordType in ("SharePointFileOperation", "OneDriveFileOperation")
    | where Operation == "SensitivityLabelApplied"
    | extend SensitivityLabel = tostring(parse_json(ModifiedProperties)[0].NewValue)
    | where SensitivityLabel in~ (sensitiveLabels)
    | summarize SensitivityLabelInfo = take_any(SensitivityLabel) by OfficeObjectId
) on OfficeObjectId
| where isnotempty(SensitivityLabelInfo)
| summarize 
    FileCount = dcount(OfficeObjectId),
    FileList = make_set(OfficeObjectId, 100),
    LastAccess = max(TimeGenerated)
    by UserId, UserAgent, ClientIP, SensitivityLabelInfo
| extend AccessLocation = tostring(parse_json(ClientIP).geoCoordinates)
| order by FileCount desc"""
        }
    ]
}

def fetch_content(url):
    """Scarica e estrae contenuto testuale da un URL utilizzando trafilatura."""
    try:
        downloaded = trafilatura.fetch_url(url)
        if downloaded:
            text = trafilatura.extract(downloaded)
            return text
        return None
    except Exception as e:
        print(f"Errore nel recupero del contenuto da {url}: {e}")
        return None

def create_example_cards(platform, examples):
    """Crea HTML per le card di esempio di query."""
    html = []
    for example in examples:
        html.append(f"""
<div class="card mb-3">
    <div class="card-header">
        <i class="fas fa-code me-2"></i><strong>{example['title']}</strong>
    </div>
    <div class="card-body">
        <p>{example['description']}</p>
        <pre><code class="language-sql">{example['query']}</code></pre>
    </div>
</div>
""")
    return '\n'.join(html)

def enrich_file_with_examples(file_path, platform, examples):
    """Aggiunge esempi di query al file HTML specificato."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Aggiungi una nuova sezione con gli esempi
        examples_html = create_example_cards(platform, examples)
        new_section = f"""
<h4 class="mt-4">Query avanzate</h4>
<p>
    Le seguenti query sono esempi avanzati di come utilizzare {platform.title()} per rilevare diverse minacce di sicurezza.
    Queste query possono essere personalizzate in base al proprio ambiente e alle proprie esigenze specifiche.
</p>

{examples_html}
"""
        
        # Aggiungi la nuova sezione prima della fine del file
        updated_content = content
        
        # Controlla se già esistono esempi avanzati
        if "Query avanzate" not in content:
            # Trova la posizione approssimativa per inserire il nuovo contenuto
            # Questa è una semplificazione - in un caso reale, si dovrebbe usare 
            # un approccio più robusto per modificare HTML
            if "</div>" in content:
                last_div_pos = content.rfind("</div>")
                updated_content = content[:last_div_pos] + new_section + content[last_div_pos:]
            else:
                updated_content = content + new_section
        
        # Scrivi il contenuto aggiornato
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(updated_content)
            
        print(f"File {file_path} aggiornato con successo!")
        return True
    except Exception as e:
        print(f"Errore nell'aggiornamento del file {file_path}: {e}")
        return False

def main():
    """Funzione principale che arricchisce i file HTML con contenuti aggiuntivi."""
    base_path = "static/partials/siem"
    
    # Assicurati che la directory esista
    if not os.path.exists(base_path):
        print(f"La directory {base_path} non esiste!")
        return False
    
    # Aggiorna ogni piattaforma con esempi aggiuntivi
    for platform, examples in QUERY_EXAMPLES.items():
        file_path = os.path.join(base_path, f"{platform}.html")
        if os.path.exists(file_path):
            print(f"Aggiornamento di {file_path} con {len(examples)} esempi...")
            enrich_file_with_examples(file_path, platform, examples)
        else:
            print(f"File {file_path} non trovato!")
    
    print("Processo di arricchimento completato!")
    return True

if __name__ == "__main__":
    main()