python2 peepdf.py a2852936a7e33787c0ab11f346631d89.pdf

Questo comando mostra la struttura del PDF e gli oggetti contenuti, come eventuali script JavaScript malevoli.

![[Pasted image 20250517171133.png]]
Per estrarre e analizzare il contenuto di uno specifico oggetto, ad esempio l’oggetto numero 18 che contiene codice JavaScript, si usa `pdf-parser` con questi parametri:

pdf-parser -f -o 18 -d codice.js  a2852936a7e33787c0ab11f346631d89.pdf

- `-o 18`: indica l’**oggetto** del PDF da estrarre, in questo caso l’oggetto numero 18, che corrisponde al codice JavaScript sospetto.
    
- `-d codice.js`: specifica il **nome del file** dove verrà salvato il contenuto estratto (il codice JavaScript in chiaro).
    
- `-f`: applica i **filtri di decompressione** per decodificare il contenuto (ad esempio FlateDecode, ASCIIHexDecode, ASCII85Decode, LZWDecode, RunLengthDecode), in modo da ottenere il codice leggibile e non compresso.

![[Pasted image 20250517171645.png]]


