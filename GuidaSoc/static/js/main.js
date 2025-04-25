document.addEventListener('DOMContentLoaded', function() {
    // Selettori principali
    const contentArea = document.getElementById('content-area');
    const navLinks = document.querySelectorAll('.nav-link');
    const sidebarLinks = document.querySelectorAll('.sidebar-link');
    const mobileNavToggle = document.getElementById('navbar-toggler');
    
    // Rende disponibile globalmente la funzione loadContent
    window.loadContent = loadContent;
    
    // Carica la home page per default
    loadContent('home');
    
    // Gestione della navigazione dalla navbar
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Rimuove la classe active da tutti i link
            navLinks.forEach(l => l.classList.remove('active'));
            
            // Aggiunge la classe active al link cliccato
            this.classList.add('active');
            
            // Ottiene la sezione da caricare dall'attributo data-section
            const section = this.getAttribute('data-section');
            
            // Carica il contenuto
            loadContent(section);
            
            // Chiude il menu hamburger su mobile quando si fa clic su un link
            if (window.innerWidth < 992 && mobileNavToggle && !mobileNavToggle.classList.contains('collapsed')) {
                mobileNavToggle.click();
            }
        });
    });
    
    // Gestione della navigazione dalla sidebar
    sidebarLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Rimuove la classe active da tutti i link della sidebar
            sidebarLinks.forEach(l => l.classList.remove('active'));
            
            // Aggiunge la classe active al link cliccato
            this.classList.add('active');
            
            // Ottiene la sezione da caricare dall'attributo data-section
            const section = this.getAttribute('data-section');
            
            // Carica il contenuto
            loadContent(section);
        });
    });
    
    // Funzione per caricare i contenuti in base alla sezione
    function loadContent(section) {
        // Mostra l'animazione di caricamento
        contentArea.innerHTML = '<div class="content-loading"><div class="spinner"></div></div>';
        
        // Carica il contenuto parziale (percorso relativo per funzionare anche offline)
        fetch(`static/partials/${section}.html`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Errore nel caricamento della pagina');
                }
                return response.text();
            })
            .then(html => {
                contentArea.innerHTML = html;
                
                // Applica highlight.js ai blocchi di codice se presenti
                if (window.hljs) {
                    document.querySelectorAll('pre code').forEach((block) => {
                        hljs.highlightElement(block);
                    });
                }
                
                // Gestisce gli eventi specifici per la sezione
                handleSectionSpecificEvents(section);
                
                // Torna all'inizio della pagina con animazione
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            })
            .catch(error => {
                console.error('Errore:', error);
                contentArea.innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        <h4 class="alert-heading">Errore di caricamento</h4>
                        <p>Non è stato possibile caricare il contenuto richiesto. Si prega di riprovare più tardi.</p>
                        <hr>
                        <p class="mb-0">Dettaglio tecnico: ${error.message}</p>
                    </div>
                `;
            });
    }
    
    // Gestisce eventi specifici per le diverse sezioni
    function handleSectionSpecificEvents(section) {
        if (section === 'siem') {
            // Inizializza i tab SIEM tramite la funzione nel file siem-tabs.js
            if (window.siem && typeof window.siem.init === 'function') {
                window.siem.init();
            } else {
                console.error('SIEM tabs module not loaded correctly');
            }
        } else if (section === 'phishing') {
            // Gestisce il decoder URL nella sezione phishing
            const decodeUrlBtn = document.getElementById('decode-url-btn');
            const urlInput = document.getElementById('phishing-url-input');
            const urlResult = document.getElementById('decoded-url-result');
            
            if (decodeUrlBtn && urlInput && urlResult) {
                decodeUrlBtn.addEventListener('click', function() {
                    const url = urlInput.value.trim();
                    if (url) {
                        try {
                            const decoded = decodeURIComponent(url);
                            urlResult.innerHTML = `
                                <div class="card mt-3">
                                    <div class="card-header">URL Decodificato</div>
                                    <div class="card-body">
                                        <code>${decoded}</code>
                                    </div>
                                </div>
                            `;
                        } catch (e) {
                            urlResult.innerHTML = `
                                <div class="alert alert-danger mt-3">
                                    Errore nella decodifica: ${e.message}
                                </div>
                            `;
                        }
                    } else {
                        urlResult.innerHTML = `
                            <div class="alert alert-warning mt-3">
                                Inserisci un URL da decodificare.
                            </div>
                        `;
                    }
                });
            }
        } else if (section === 'risorse') {
            // Gestisce eventuali azioni nella sezione risorse
            const downloadLinks = document.querySelectorAll('.download-resource');
            
            downloadLinks.forEach(link => {
                link.addEventListener('click', function(e) {
                    // Puoi aggiungere qui la logica per tracciare i download se necessario
                    console.log(`Risorsa scaricata: ${this.getAttribute('data-resource')}`);
                });
            });
        }
    }
    
    // Gestisce la ricerca nel glossario
    const glossarySearchInput = document.getElementById('glossary-search');
    if (glossarySearchInput) {
        glossarySearchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const glossaryItems = document.querySelectorAll('.glossary-item');
            
            glossaryItems.forEach(item => {
                const term = item.querySelector('.term').textContent.toLowerCase();
                const description = item.querySelector('.description').textContent.toLowerCase();
                
                if (term.includes(searchTerm) || description.includes(searchTerm)) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    }
});
