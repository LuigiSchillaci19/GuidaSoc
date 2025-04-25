document.addEventListener('DOMContentLoaded', function() {
    // Gestisce i tab specifici della sezione SIEM quando sono caricati
    function initSiemTabs() {
        const siemTabs = document.querySelectorAll('.siem-tab');
        const siemContents = document.querySelectorAll('.siem-content');
        const siemSidebar = document.getElementById('siem-sidebar');
        
        // Se non ci sono tab SIEM nella pagina, non fare nulla
        if (siemTabs.length === 0) return;

        console.log('SIEM Tabs inizializzati');
        
        // Carica la sidebar SIEM (percorso relativo per funzionare offline)
        fetch('static/partials/siem/sidebar.html')
            .then(response => response.text())
            .then(html => {
                if (siemSidebar) {
                    siemSidebar.innerHTML = html;
                }
            })
            .catch(error => console.error('Errore caricamento sidebar:', error));
        
        // Carica il contenuto del tab attivo per default (Splunk)
        const defaultTab = document.querySelector('.siem-tab.active');
        if (defaultTab) {
            loadSiemContent(defaultTab.getAttribute('data-target'));
        }
        
        // Aggiungi eventi click a tutti i tab
        siemTabs.forEach(tab => {
            tab.addEventListener('click', function() {
                const target = this.getAttribute('data-target');
                
                // Nascondi tutti i contenuti e rimuovi active da tutti i tab
                siemTabs.forEach(t => t.classList.remove('active'));
                siemContents.forEach(c => {
                    c.classList.remove('show', 'active');
                    // Svuota il contenuto per evitare sovrapposizioni
                    if (c.id !== target) {
                        c.innerHTML = '';
                    }
                });
                
                // Attiva il tab selezionato e mostra il suo contenuto
                this.classList.add('active');
                const targetContent = document.getElementById(target);
                targetContent.classList.add('show', 'active');
                
                // Carica il contenuto specifico della piattaforma selezionata
                loadSiemContent(target);
            });
        });
    }
    
    // Funzione per caricare il contenuto specifico di ogni piattaforma SIEM
    function loadSiemContent(platform) {
        const contentDiv = document.getElementById(platform);
        
        if (contentDiv) {
            // Mostra spinner di caricamento
            contentDiv.innerHTML = '<div class="content-loading"><div class="spinner"></div></div>';
            
            fetch(`static/partials/siem/${platform}.html`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`Errore nel caricamento dei contenuti per ${platform}`);
                    }
                    return response.text();
                })
                .then(html => {
                    contentDiv.innerHTML = html;
                    
                    // Applica highlight.js ai blocchi di codice
                    if (window.hljs) {
                        contentDiv.querySelectorAll('pre code').forEach((block) => {
                            try {
                                hljs.highlightElement(block);
                            } catch (err) {
                                console.error('Errore highlight:', err);
                            }
                        });
                    }
                })
                .catch(error => {
                    console.error(`Errore caricamento ${platform}:`, error);
                    contentDiv.innerHTML = `
                        <div class="alert alert-danger">
                            <h5>Errore di caricamento</h5>
                            <p>Impossibile caricare il contenuto per ${platform}.</p>
                            <small>${error.message}</small>
                        </div>
                    `;
                });
        }
    }
    
    // Controlla periodicamente se ci sono tab SIEM nella pagina e inizializzali
    function checkForSiemTabs() {
        const siemTabsElement = document.getElementById('siemTabs');
        if (siemTabsElement) {
            initSiemTabs();
        }
    }
    
    // Inizializza i tab SIEM se presente la sezione
    checkForSiemTabs();
    
    // Esponi funzioni per l'uso esterno
    window.siem = {
        init: initSiemTabs,
        loadContent: loadSiemContent
    };
});