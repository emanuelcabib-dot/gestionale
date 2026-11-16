# Gestionale

## Configurazione accesso

Nel Cloudflare Worker configura i secrets `COMPANY_USERNAME` e `COMPANY_PASSWORD`. Il primo e' il nome utente accettato, il secondo e' la password condivisa; nessuna delle due credenziali viene inserita nel client.

Per usare l'accesso biometrico, crea un namespace Cloudflare KV e aggiungilo al Worker con il binding chiamato esattamente `AUTH_KV`. Le credenziali pubbliche e le sfide temporanee WebAuthn vengono salvate in questo namespace.

Il Worker conserva inoltre in KV solo l'impronta SHA-256 della password aziendale. Quando rileva una modifica al secret `COMPANY_PASSWORD`, cancella le passkey dell'utente; il controllo avviene al successivo login con password o richiesta WebAuthn.

La pagina deve essere pubblicata su HTTPS. Le credenziali biometriche sono associate all'origine web e all'username configurato; registrale nuovamente per ogni dispositivo/browser.

## Gestione documenti PDF

I PDF sono salvati come Base64 nella tabella Grist `Documenti_PDF`. Al primo uso, il Worker crea la tabella e le colonne mancanti `ID`, `Nome`, `Contenuto_Base64`, `MimeType`, `Data_Caricamento` e `Dimensione`; le colonne esistenti con tipo incompatibile causano un errore esplicito. Il Worker usa i secrets Grist già configurati (`GRIST_DOC_ID` e `GRIST_API_KEY`); non servono binding R2 o credenziali Google.

Il Worker accetta solo PDF fino a 10 MB e protegge upload, elenco e download con il sessionToken dell'app. La lista esclude il contenuto Base64 e recupera il contenuto solo per il documento richiesto. La sessione frontend viene chiusa dopo cinque minuti senza interazione.
