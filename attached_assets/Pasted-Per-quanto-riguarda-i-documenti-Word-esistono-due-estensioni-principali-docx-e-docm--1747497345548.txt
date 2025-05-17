Per quanto riguarda i documenti Word, esistono due estensioni principali: **.docx** e **.docm**.

- I file **.docx** non possono contenere macro VBA direttamente, essendo un formato "macro-free". Tuttavia, un documento `.docx` può fare riferimento a un template esterno **.dotm** che include macro, permettendo l’esecuzione di codice VBA.
    
- Il formato **.docm**, invece, supporta direttamente macro VBA integrate nel file. Questa differenza è importante per riconoscere potenziali rischi di sicurezza legati ai documenti Word.

## Per i file DOCM
Per analizzare le macro VBA o contenuti malevoli presenti in un file `.docm`, puoi utilizzare il comando:

oledump.py file.docm

Questo permette di identificare eventuali flussi VBA all’interno del documento.

![[Pasted image 20250517160802.png]]
Se vuoi visualizzare il contenuto di un modulo VBA specifico (ad esempio, il flusso 3) e filtrare solo le stringhe leggibili:

oledump.py -s 3 -S 7085f3dda26b773120d4da2362f5a2e95af799dcec8ec580d36c9d77a6abda4d.docm

![[Pasted image 20250517160904.png]]

C:\Users\kali\Desktop>oledump.py -s 3 --vbadecompresscorrupt 7085f3dda26b773120d4da2362f5a2e95af799dcec8ec580d36c9d77a6abda4d.docm
**`--vbadecompresscorrupt`**: è un’opzione avanzata di oledump.py che serve per **decomprimere moduli VBA corrotti o danneggiati**.

![[Pasted image 20250517161030.png]]


## Per i file DOC

Come spiegato all'inizio, i file `.doc` non mostrano macro direttamente tramite `oledump.py`.
![[Pasted image 20250517162502.png]]

Come si analizza un file doc:
- **Rinomina l'estensione del file da `.doc` a `.zip`.**
- 1. Apri l'archivio `.zip`.
![[Pasted image 20250517162624.png]]

3. Naviga nella directory `word -> rels`.
![[Pasted image 20250517162753.png]]
4. Nel file `settings.xml.rels`, troverai l’indirizzo del template remoto.

![[Pasted image 20250517162955.png]]

5. Analizza l’**URL presente nel target** per identificare eventuali template malevoli.
![[Pasted image 20250517163547.png]]


TIPS:
Per automatizzare l’analisi delle macro VBA in documenti Office, un tool molto efficace è **olevba**.

Con un semplice comando da terminale è possibile estrarre il codice e rilevare indicatori di attività sospette.  

Questo strumento è utile per velocizzare l’analisi di malware basato su macro.  
Ecco un esempio di comando per analizzare un file `.docm`

![[Pasted image 20250517173650.png]]
Playbook:
## RACCOLTA INFORMAZIONI (Metadata Analysis)

- **Identificazione del tipo di file**:
    
    - Esegui il comando `file <documento>` per verificare l'effettiva estensione e integrità del file.
        
    - Usa `exiftool <documento>` per analizzare i metadati (autore, timestamp, software di creazione).
        
- **Hashing e identificazione**:
    
    - Calcola l'hash del file con `sha256sum <documento>` per identificazioni successive.
        
    - Verifica su **VirusTotal**, **Malshare** o **Hybrid Analysis** per indicatori noti.
        

---

## 2️⃣ ANALISI STATICA (Static Analysis)

### 🔹 PDF:

- **pdfid**: Identifica oggetti sospetti (`/JS`, `/JavaScript`, `/OpenAction`, `/AA`).
    
    - Esempio: `pdfid <documento.pdf>`
        
- **pdf-parser**: Estrae e analizza oggetti specifici.
    
    - Esempio: `pdf-parser -o 1 <documento.pdf>` per vedere l'oggetto 1.
        
- **peepdf**: GUI interattiva per navigare nel PDF.
    

### 🔹 Word/Excel:

- **olevba**: Estrazione di macro VBA.
    
    - Esempio: `olevba <documento.docm>`
        
- **oledump.py**: per macro e oggetti nascosti.
    
    - Esempio: `oledump.py <documento.doc>`