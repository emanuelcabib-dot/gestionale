# Gestionale

## Configurazione accesso

Nel Cloudflare Worker configura i secrets `COMPANY_USERNAME` e `COMPANY_PASSWORD`. Il primo e' il nome utente accettato, il secondo e' la password condivisa; nessuna delle due credenziali viene inserita nel client.

Per usare l'accesso biometrico, crea un namespace Cloudflare KV e aggiungilo al Worker con il binding chiamato esattamente `AUTH_KV`. Le credenziali pubbliche e le sfide temporanee WebAuthn vengono salvate in questo namespace.

Il Worker conserva inoltre in KV solo l'impronta SHA-256 della password aziendale. Quando rileva una modifica al secret `COMPANY_PASSWORD`, cancella le passkey dell'utente; il controllo avviene al successivo login con password o richiesta WebAuthn.

La pagina deve essere pubblicata su HTTPS. Le credenziali biometriche sono associate all'origine web e all'username configurato; registrale nuovamente per ogni dispositivo/browser.

## Gestione documenti PDF

Per aprire la cartella condivisa su Google Drive, configura nel Worker la variabile `DRIVE_PDF_URL` con un URL HTTPS di `drive.google.com` o `docs.google.com`. L'indirizzo viene restituito solo alle sessioni autorizzate.
