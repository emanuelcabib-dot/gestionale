# Gestionale

## Configurazione accesso

Nel Cloudflare Worker configura i secrets `COMPANY_USERNAME` e `COMPANY_PASSWORD`. Il primo e' il nome utente accettato, il secondo e' la password condivisa; nessuna delle due credenziali viene inserita nel client.

Per usare l'accesso biometrico, crea un namespace Cloudflare KV e aggiungilo al Worker con il binding chiamato esattamente `AUTH_KV`. Le credenziali pubbliche e le sfide temporanee WebAuthn vengono salvate in questo namespace.

Il Worker conserva inoltre in KV solo l'impronta SHA-256 della password aziendale. Quando rileva una modifica al secret `COMPANY_PASSWORD`, cancella le passkey dell'utente; il controllo avviene al successivo login con password o richiesta WebAuthn.

La pagina deve essere pubblicata su HTTPS. Le credenziali biometriche sono associate all'origine web e all'username configurato; registrale nuovamente per ogni dispositivo/browser.

## Gestione documenti PDF

I PDF sono caricati come allegati Grist e associati alla colonna di tipo `Attachments` `Allegato` nella tabella `Documenti_PDF`. La tabella deve essere predisposta con le colonne `ID`, `Nome`, `Allegato`, `MimeType`, `Data_Caricamento` e `Dimensione`. Il Worker usa i secrets Grist già configurati (`GRIST_DOC_ID` e `GRIST_API_KEY`); non servono binding R2 o credenziali Google.

Il Worker accetta solo PDF fino a 10 MB, inoltra gli upload multipart all'API allegati di Grist e associa l'ID dell'allegato al record. Upload, elenco e download sono protetti dal sessionToken dell'app. La sessione frontend viene chiusa dopo cinque minuti senza interazione.
