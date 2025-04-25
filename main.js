document.addEventListener('DOMContentLoaded', function() {
    // Selettori principali
    const contentArea = document.getElementById('content-area');
    const navLinks = document.querySelectorAll('.nav-link');
    const mobileNavToggle = document.getElementById('navbar-toggler');
    
    // Rende disponibile globalmente la funzione loadContent
    window.loadContent = loadContent;
    
    // Carica la home page per default
    loadContent('home');
    
    // Gestione della navigazione dalla navbar
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // Evento già gestito con onclick nel HTML, assicuriamo solo che tutte le classi siano aggiornate
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            
            // Chiude il menu hamburger su mobile quando si fa clic su un link
            if (window.innerWidth < 992 && mobileNavToggle && !mobileNavToggle.classList.contains('collapsed')) {
                mobileNavToggle.click();
            }
        });
    });
    
    // Funzione per caricare i contenuti in base alla sezione
    function loadContent(section) {
        // Mostra l'animazione di caricamento
        contentArea.innerHTML = '<div class="content-loading"><div class="spinner"></div></div>';
        
        // Carica il contenuto parziale (tutti i file sono nella directory principale)
        fetch(`${section}.html`)
            .then(response => {
                if (!response.ok) {
                    console.error(`Non è stato possibile caricare ${section}.html`);
                    throw new Error('Errore nel caricamento della pagina');
                }
                return response.text();
            })
            .then(html => {
                contentArea.innerHTML = html;
                
                // Aggiorna la navigazione
                navLinks.forEach(link => {
                    if (link.textContent.trim().toLowerCase().includes(section)) {
                        link.classList.add('active');
                    } else {
                        link.classList.remove('active');
                    }
                });
                
                // Aggiorna i link della sidebar se presenti
                const sidebarLinks = document.querySelectorAll('.sidebar-link');
                if (sidebarLinks.length > 0) {
                    sidebarLinks.forEach(link => {
                        link.addEventListener('click', function(e) {
                            e.preventDefault();
                            const target = this.getAttribute('href').replace('#', '');
                            loadContent(target);
                            
                            // Aggiorna classi attive nella sidebar
                            sidebarLinks.forEach(l => l.classList.remove('active'));
                            this.classList.add('active');
                        });
                    });
                }
                
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
        } else if (section === 'eventcode') {
            // Gestione dei tab per Event Code se presenti
            const eventCodeTabs = document.querySelectorAll('.event-code-tab');
            if (eventCodeTabs.length > 0) {
                eventCodeTabs.forEach(tab => {
                    tab.addEventListener('click', function() {
                        const target = this.getAttribute('data-bs-target');
                        
                        // Rimuove active da tutti i tab
                        eventCodeTabs.forEach(t => t.classList.remove('active'));
                        
                        // Nascondi tutti i pannelli
                        document.querySelectorAll('.tab-pane').forEach(pane => {
                            pane.classList.remove('show', 'active');
                        });
                        
                        // Attiva il tab e il pannello selezionato
                        this.classList.add('active');
                        document.querySelector(target).classList.add('show', 'active');
                    });
                });
            }
        } else if (section === 'glossario') {
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
        }
    }
});