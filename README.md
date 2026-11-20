# Gestionale

## Configurazione accesso

Nel Cloudflare Worker configura i secrets `COMPANY_USERNAME` e `COMPANY_PASSWORD`. Il primo e' il nome utente accettato, il secondo e' la password condivisa; nessuna delle due credenziali viene inserita nel client.

Per usare l'accesso biometrico, crea un namespace Cloudflare KV e aggiungilo al Worker con il binding chiamato esattamente `AUTH_KV`. Le credenziali pubbliche, le sfide temporanee WebAuthn e i token di sessione vengono salvati in questo namespace. I token sono casuali e scadono dopo 24 ore; il logout li revoca.

Per rilevare modifiche alla password, il Worker conserva in KV la sua impronta SHA-256, non la password. Quando rileva una modifica al secret `COMPANY_PASSWORD`, cancella le passkey dell'utente; il controllo avviene al successivo login con password o richiesta WebAuthn.

La pagina deve essere pubblicata su HTTPS. Le credenziali biometriche sono associate all'origine web e all'username configurato; registrale nuovamente per ogni dispositivo/browser.

Configura `ALLOWED_ORIGINS` con le origini web autorizzate separate da virgole (per esempio `https://emanuelcabib-dot.github.io`). Se la variabile manca o è vuota, è consentita solo l'origine GitHub Pages predefinita.

## Verifica in due fattori

La scheda **Impostazioni → Sicurezza & 2FA** consente di configurare un'app Authenticator compatibile con RFC 6238, consultare i codici di backup residui, rigenerare i codici e revocare i dispositivi attendibili. L'attivazione richiede la verifica di un codice TOTP. I codici di backup vengono mostrati una sola volta: conservali fuori dall'applicazione.

Il Worker genera e verifica i codici TOTP e conserva in `AUTH_KV` il segreto, gli hash salati dei codici di backup, le sfide temporanee e gli hash dei token dei dispositivi. I parametri di sicurezza (durate, tolleranza TOTP e limiti dei tentativi) sono definiti nel Worker. I dispositivi attendibili scadono dopo 30 giorni. L'URI TOTP è usato esclusivamente nel browser per disegnare il QR; non viene inviato a un servizio QR.

## Gestione documenti PDF

Per aprire la cartella condivisa su Google Drive, configura nel Worker la variabile `DRIVE_PDF_URL` con un URL HTTPS di `drive.google.com` o `docs.google.com`. L'indirizzo viene restituito solo alle sessioni autorizzate.
