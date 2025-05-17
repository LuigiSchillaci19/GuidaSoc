
1. unzip file.xlsm (estraiamo tutti i file e le cartelle che sono compressi all’interno del file `.xlsm`)

Dentro vedrai cartelle come:

- `xl/` — contiene fogli di lavoro, macro (`vbaProject.bin`), e altro
    
- `docProps/` — proprietà del documento
    
- `_rels/` — file di relazioni tra componenti
    
- `[Content_Types].xml` — informazioni sul tipo di contenuto

2. oledump.py file.xsml (utile per identificare e analizzare macro VBA o eventuali contenuti malevoli all’interno del file Excel.)

![[Pasted image 20250517165025.png]]

la M Indica un **modulo standard** VBA, cioè un modulo contenente **codice VBA scritto dall’utente** che non è legato a un particolare oggetto come un foglio o il workbook.

La m Indica un **modulo di classe o modulo oggetto**, ovvero un modulo VBA associato a un **oggetto specifico** nel file Excel. Es: il workbook stesso (`ThisWorkbook`)  
Questi moduli contengono codice VBA legato a eventi o comportamenti specifici di quell’oggetto, ad esempio cosa succede quando apri il foglio o il workbook

oledump.py -s 4 sampleExcelFile.xlsm (con questo comando stiamo visualizzando le stringhe di Module1)
![[Pasted image 20250517165118.png]]
Aggiungendo -S al comando si visualizza il contenuto del modulo 4 **decodificato e più leggibile**, mostrando **solo le stringhe di testo** presenti nel modulo VBA, **filtrando via il codice VBA e altri dati binari**.
![[Pasted image 20250517165149.png]]

C:\Users\kali\Desktop>oledump.py -s 4 --vbadecompresscorrupt sampleExcelFile.xlsm
**`--vbadecompresscorrupt`**: è un’opzione avanzata di oledump.py che serve per **decomprimere moduli VBA corrotti o danneggiati**.

![[Pasted image 20250517165206.png]]

Come in word anche un file Excel `.xlsx` o `.xlsm` può puntare a un template esterno di tipo **`.xltm`**. Questo template può essere caricato da un percorso remoto specificato all'interno del file Excel stesso. Se compromesso, può eseguire macro malevole al momento dell'apertura.

