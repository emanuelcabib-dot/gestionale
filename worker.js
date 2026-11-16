const textEncoder = new TextEncoder();

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Valore WebAuthn non valido");
  }
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function encodeCredentialId(username) {
  return encodeURIComponent(username);
}

function jsonResponse(data, corsHeaders, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

function privateJsonResponse(data, corsHeaders, status = 200) {
  const response = jsonResponse(data, corsHeaders, status);
  response.headers.set("Cache-Control", "private, no-store");
  return response;
}

function equalSecret(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string") return false;
  const actualBytes = textEncoder.encode(actual);
  const expectedBytes = textEncoder.encode(expected);
  let difference = actualBytes.length ^ expectedBytes.length;
  const length = Math.max(actualBytes.length, expectedBytes.length);
  for (let i = 0; i < length; i++) {
    difference |= (actualBytes[i] || 0) ^ (expectedBytes[i] || 0);
  }
  return difference === 0;
}

function getWebAuthnContext(request) {
  const origin = request.headers.get("Origin");
  if (!origin) throw new Error("Origine WebAuthn mancante");
  const parsedOrigin = new URL(origin);
  if (parsedOrigin.origin !== origin || (parsedOrigin.protocol !== "https:" && parsedOrigin.hostname !== "localhost")) {
    throw new Error("Origine WebAuthn non valida");
  }
  return { origin, rpId: parsedOrigin.hostname };
}

async function createWebAuthnChallenge(env, username, purpose, context) {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  const challengeString = base64UrlEncode(challenge);
  await env.AUTH_KV.put(`challenge:${challengeString}`, JSON.stringify({
    username,
    purpose,
    origin: context.origin,
    rpId: context.rpId
  }), { expirationTtl: 300 });
  return challengeString;
}

async function consumeWebAuthnChallenge(env, challenge, username, purpose) {
  const key = `challenge:${challenge}`;
  const value = await env.AUTH_KV.get(key);
  if (value) await env.AUTH_KV.delete(key);
  if (!value) return null;
  const record = JSON.parse(value);
  return record.username === username && record.purpose === purpose ? record : null;
}

function decodeCbor(bytes, start = 0) {
  let offset = start;
  const readLength = additional => {
    if (additional < 24) return additional;
    const sizes = { 24: 1, 25: 2, 26: 4, 27: 8 };
    const size = sizes[additional];
    if (!size || offset + size > bytes.length) throw new Error("CBOR non valido");
    let length = 0;
    for (let i = 0; i < size; i++) length = length * 256 + bytes[offset++];
    return length;
  };
  const parse = depth => {
    if (depth > 20 || offset >= bytes.length) throw new Error("CBOR non valido");
    const initial = bytes[offset++];
    const major = initial >> 5;
    const additional = initial & 31;
    if (major === 7) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      throw new Error("Valore CBOR non supportato");
    }
    const length = readLength(additional);
    if (major === 0) return length;
    if (major === 1) return -1 - length;
    if (major === 2 || major === 3) {
      if (length > bytes.length - offset) throw new Error("CBOR non valido");
      const value = bytes.slice(offset, offset + length);
      offset += length;
      return major === 2 ? value : new TextDecoder().decode(value);
    }
    if (major === 4) {
      const values = [];
      for (let i = 0; i < length; i++) values.push(parse(depth + 1));
      return values;
    }
    if (major === 5) {
      const values = new Map();
      for (let i = 0; i < length; i++) values.set(parse(depth + 1), parse(depth + 1));
      return values;
    }
    if (major === 6) return parse(depth + 1);
    throw new Error("CBOR non valido");
  };
  const value = parse(0);
  return { value, bytesRead: offset - start };
}

function parseAuthenticatorData(bytes, requireAttestedCredential = false) {
  if (bytes.length < 37) throw new Error("Dati autenticatore incompleti");
  const flags = bytes[32];
  if (!(flags & 0x01) || !(flags & 0x04)) throw new Error("Biometria o verifica utente non confermata");
  const signCount = new DataView(bytes.buffer, bytes.byteOffset + 33, 4).getUint32(0);
  const result = { flags, signCount };
  if (!requireAttestedCredential) return result;
  if (!(flags & 0x40) || bytes.length < 55) throw new Error("Credenziale WebAuthn non presente");
  const credentialLength = new DataView(bytes.buffer, bytes.byteOffset + 53, 2).getUint16(0);
  const credentialStart = 55;
  const credentialEnd = credentialStart + credentialLength;
  if (!credentialLength || credentialEnd >= bytes.length) throw new Error("ID credenziale non valido");
  const credentialId = bytes.slice(credentialStart, credentialEnd);
  const coseStart = credentialEnd;
  const decodedKey = decodeCbor(bytes, coseStart);
  return {
    ...result,
    credentialId,
    coseKey: decodedKey.value,
    coseBytes: bytes.slice(coseStart, coseStart + decodedKey.bytesRead)
  };
}

async function assertRpIdHash(authenticatorData, rpId) {
  const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", textEncoder.encode(rpId)));
  const actual = authenticatorData.slice(0, 32);
  return actual.length === expected.length && actual.every((byte, index) => byte === expected[index]);
}

async function verifyClientData(clientDataBytes, expectedType, challenge, context) {
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  if (clientData.type !== expectedType ||
      clientData.challenge !== challenge ||
      clientData.origin !== context.origin ||
      clientData.crossOrigin === true) {
    throw new Error("Risposta WebAuthn non valida");
  }
}

function credentialPublicKey(coseKey) {
  if (!(coseKey instanceof Map)) throw new Error("Chiave pubblica WebAuthn non valida");
  const keyType = coseKey.get(1);
  const algorithm = coseKey.get(3);
  if (keyType === 2 && algorithm === -7 && coseKey.get(-1) === 1) {
    const x = coseKey.get(-2);
    const y = coseKey.get(-3);
    if (!(x instanceof Uint8Array) || x.length !== 32 || !(y instanceof Uint8Array) || y.length !== 32) {
      throw new Error("Chiave ES256 non valida");
    }
    return {
      algorithm,
      jwk: {
        kty: "EC",
        crv: "P-256",
        x: base64UrlEncode(x),
        y: base64UrlEncode(y),
        ext: true
      }
    };
  }
  if (keyType === 3 && algorithm === -257) {
    const modulus = coseKey.get(-1);
    const exponent = coseKey.get(-2);
    if (!(modulus instanceof Uint8Array) || !(exponent instanceof Uint8Array)) {
      throw new Error("Chiave RS256 non valida");
    }
    return {
      algorithm,
      jwk: {
        kty: "RSA",
        n: base64UrlEncode(modulus),
        e: base64UrlEncode(exponent),
        alg: "RS256",
        ext: true
      }
    };
  }
  throw new Error("Algoritmo WebAuthn non supportato");
}

function derEcdsaToRaw(signature) {
  if (signature.length === 64) return signature;
  if (signature.length < 8 || signature.length > 72 ||
      signature[0] !== 0x30 || signature[1] !== signature.length - 2) {
    throw new Error("Firma ECDSA non valida");
  }
  let offset = 2;
  const normalize = value => {
    let start = 0;
    while (start < value.length - 32 && value[start] === 0) start++;
    const trimmed = value.slice(start);
    if (trimmed.length > 32) throw new Error("Firma ECDSA non valida");
    const padded = new Uint8Array(32);
    padded.set(trimmed, 32 - trimmed.length);
    return padded;
  };
  const readInteger = () => {
    if (signature[offset++] !== 0x02) throw new Error("Firma ECDSA non valida");
    const length = signature[offset++];
    if (!length || length > 33 || offset + length > signature.length) throw new Error("Firma ECDSA non valida");
    const value = signature.slice(offset, offset + length);
    offset += length;
    if ((value[0] & 0x80) || (value.length > 1 && value[0] === 0 && !(value[1] & 0x80))) {
      throw new Error("Firma ECDSA non valida");
    }
    return normalize(value);
  };
  const r = readInteger();
  const s = readInteger();
  if (offset !== signature.length) throw new Error("Firma ECDSA non valida");
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

async function verifyAssertionSignature(credential, authenticatorData, clientDataJSON, signature) {
  const key = await crypto.subtle.importKey(
    "jwk",
    credential.publicKey,
    credential.algorithm === -7 ? { name: "ECDSA", namedCurve: "P-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
  const signedData = new Uint8Array(authenticatorData.length + clientDataHash.length);
  signedData.set(authenticatorData);
  signedData.set(clientDataHash, authenticatorData.length);
  const signatureBytes = credential.algorithm === -7 ? derEcdsaToRaw(signature) : signature;
  const algorithm = credential.algorithm === -7 ? { name: "ECDSA", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5" };
  return crypto.subtle.verify(algorithm, key, signatureBytes, signedData);
}

async function listCredentials(env, username) {
  const prefix = `credential:${encodeCredentialId(username)}:`;
  const keys = [];
  let cursor;
  do {
    const page = await env.AUTH_KV.list({ prefix, cursor, limit: 1000 });
    keys.push(...page.keys);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return keys;
}

async function syncPasswordVersion(env, username) {
  const versionKey = `password-version:${encodeCredentialId(username)}`;
  const passwordVersion = base64UrlEncode(
    new Uint8Array(await crypto.subtle.digest("SHA-256", textEncoder.encode(env.COMPANY_PASSWORD)))
  );
  const previousVersion = await env.AUTH_KV.get(versionKey);
  if (previousVersion && !equalSecret(previousVersion, passwordVersion)) {
    const credentials = await listCredentials(env, username);
    for (const credential of credentials) {
      await env.AUTH_KV.delete(credential.name);
    }
  }
  await env.AUTH_KV.put(versionKey, passwordVersion);
}

function issueSession(env, corsHeaders) {
  const sessionToken = btoa(env.GRIST_API_KEY).substring(0, 30);
  return jsonResponse({
    success: true,
    token: sessionToken,
    urls: { dashboard: env.URL_DASHBOARD, impostazioni: env.URL_IMPOSTAZIONI }
  }, corsHeaders);
}

const MAX_PDF_SIZE = 10 * 1024 * 1024;
const MAX_PDF_REQUEST_SIZE = MAX_PDF_SIZE + 128 * 1024;
const GRIST_API_BASE = "https://gestionale-lavoro-emanuel-00.getgrist.com/api";
const PDF_TABLE_ID = "Documenti_PDF";
const PDF_ATTACHMENT_COLUMN = "Allegato";

function isSessionAuthorized(request, env, bodyToken) {
  if (!env.GRIST_API_KEY) return false;
  const expectedToken = btoa(env.GRIST_API_KEY).substring(0, 30);
  const authorization = request.headers.get("Authorization") || "";
  const headerToken = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  return equalSecret(bodyToken || headerToken, expectedToken);
}

function getGristPdfContext(env) {
  if (!env.GRIST_DOC_ID || !env.GRIST_API_KEY) {
    throw new Error("Configurazione Grist incompleta sul Worker");
  }
  const documentUrl = `${GRIST_API_BASE}/docs/${encodeURIComponent(env.GRIST_DOC_ID)}`;
  return {
    documentUrl,
    headers: { Authorization: `Bearer ${env.GRIST_API_KEY}` }
  };
}

async function ensureGristPdfTable(env) {
  const { documentUrl, headers } = getGristPdfContext(env);
  const response = await fetch(`${documentUrl}/tables`, { headers });
  if (!response.ok) throw new Error("Impossibile verificare le tabelle Grist");
  const data = await response.json();
  const tables = Array.isArray(data.tables) ? data.tables : [];
  if (!tables.some(table => table.id === PDF_TABLE_ID)) {
    throw new Error("Tabella Documenti_PDF non trovata in Grist");
  }
  return { documentUrl, headers };
}

function getGristSqlRows(data) {
  if (Array.isArray(data.records)) {
    return data.records.map(record => record.fields || record);
  }
  if (Array.isArray(data.rows) && Array.isArray(data.columns)) {
    const columnNames = data.columns.map(column => typeof column === "string" ? column : column.id || column.name);
    if (columnNames.some(name => typeof name !== "string")) {
      throw new Error("Formato risultati SQL Grist non valido");
    }
    return data.rows.map(row => {
      if (!Array.isArray(row)) return row;
      return Object.fromEntries(columnNames.map((name, index) => [name, row[index]]));
    });
  }
  throw new Error("Formato risultati SQL Grist non riconosciuto");
}

async function listGristPdfs(env) {
  const { documentUrl, headers } = await ensureGristPdfTable(env);
  const files = [];
  const limit = 1000;
  for (let offset = 0; ; offset += limit) {
    const response = await fetch(`${documentUrl}/sql`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({
        sql: `SELECT "ID", "Nome", "MimeType", "Data_Caricamento", "Dimensione" FROM "${PDF_TABLE_ID}" LIMIT ${limit} OFFSET ${offset}`
      })
    });
    if (!response.ok) throw new Error("Errore durante il recupero dei documenti da Grist");
    const rows = getGristSqlRows(await response.json());
    for (const fields of rows) {
      if (typeof fields.ID !== "string" ||
          !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(fields.ID)) continue;
      files.push({
        id: fields.ID,
        name: safePdfName(fields.Nome),
        size: Number(fields.Dimensione) || 0,
        modifiedTime: String(fields.Data_Caricamento || "")
      });
    }
    if (rows.length < limit) break;
  }
  return files;
}

function safePdfName(value) {
  let name = String(value || "documento.pdf")
    .replace(/[\/\\\u0000-\u001f\u007f]/g, "_")
    .trim();
  if (!name || !/\.pdf$/i.test(name)) name = `${name || "documento"}.pdf`;
  if (name.length > 180) name = `${name.slice(0, 176)}.pdf`;
  return name;
}

async function readBoundedRequestBody(request, maxSize) {
  const contentLengthHeader = request.headers.get("Content-Length");
  const contentLength = Number(contentLengthHeader);
  if (contentLengthHeader && Number.isFinite(contentLength) && contentLength > maxSize) {
    return { error: "Il PDF supera la dimensione massima di 10 MB", status: 413 };
  }
  if (!request.body) return { error: "Body della richiesta mancante", status: 400 };
  const reader = request.body.getReader();
  const chunks = [];
  let totalSize = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalSize += value.byteLength;
    if (totalSize > maxSize) {
      await reader.cancel();
      return { error: "Il PDF supera la dimensione massima di 10 MB", status: 413 };
    }
    chunks.push(value);
  }
  const body = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const boundedHeaders = new Headers(request.headers);
    boundedHeaders.delete("Content-Length");
    const boundedRequest = new Request(request.url, {
      method: request.method,
      headers: boundedHeaders,
      body
    });
    return { formData: await boundedRequest.formData() };
  } catch {
    return { error: "FormData non valido nel body", status: 400 };
  }
}

async function uploadGristPdf(request, env, corsHeaders) {
  if (!isSessionAuthorized(request, env)) {
    return privateJsonResponse({ success: false, error: "Sessione non autorizzata o scaduta" }, corsHeaders, 403);
  }
  const parsed = await readBoundedRequestBody(request, MAX_PDF_REQUEST_SIZE);
  if (parsed.error) {
    return privateJsonResponse({ success: false, error: parsed.error }, corsHeaders, parsed.status);
  }
  const file = parsed.formData.get("file");
  if (!file || typeof file === "string" || file.size === 0) {
    return privateJsonResponse({ success: false, error: "Seleziona un PDF valido entro 10 MB" }, corsHeaders, 400);
  }
  if (file.size > MAX_PDF_SIZE) {
    return privateJsonResponse({ success: false, error: "Il PDF supera la dimensione massima di 10 MB" }, corsHeaders, 413);
  }
  if (file.type !== "application/pdf" && !file.name.toLowerCase().endsWith(".pdf")) {
    return privateJsonResponse({ success: false, error: "Il file selezionato non è un PDF" }, corsHeaders, 400);
  }
  const signature = new Uint8Array(await file.slice(0, 5).arrayBuffer());
  if (new TextDecoder().decode(signature) !== "%PDF-") {
    return privateJsonResponse({ success: false, error: "Il contenuto del file non è un PDF valido" }, corsHeaders, 400);
  }

  const name = safePdfName(file.name);
  const pdfFile = new File([file], name, { type: "application/pdf" });
  const gristUpload = new FormData();
  gristUpload.append("upload", pdfFile, name);
  const { documentUrl, headers } = await ensureGristPdfTable(env);
  const attachmentResponse = await fetch(`${documentUrl}/attachments`, {
    method: "POST",
    headers,
    body: gristUpload
  });
  if (!attachmentResponse.ok) {
    throw new Error("Errore durante il caricamento dell'allegato PDF su Grist");
  }
  const attachmentIds = await attachmentResponse.json();
  const attachmentId = Array.isArray(attachmentIds) ? attachmentIds[0] : null;
  if (!Number.isSafeInteger(attachmentId) || attachmentId <= 0) {
    throw new Error("Grist non ha restituito un ID allegato valido");
  }

  const id = crypto.randomUUID();
  const recordsUrl = `${documentUrl}/tables/${encodeURIComponent(PDF_TABLE_ID)}/records`;
  const recordResponse = await fetch(recordsUrl, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({
      records: [{
        fields: {
          ID: id,
          Nome: name,
          MimeType: "application/pdf",
          Data_Caricamento: new Date().toISOString(),
          Dimensione: file.size
        }
      }]
    })
  });
  if (!recordResponse.ok) {
    throw new Error("Errore durante il salvataggio del PDF in Grist");
  }
  const recordData = await recordResponse.json();
  const recordId = recordData.records?.[0]?.id;
  if (!Number.isSafeInteger(recordId) || recordId <= 0) {
    throw new Error("Grist non ha restituito l'ID del record del documento");
  }
  const patchResponse = await fetch(recordsUrl, {
    method: "PATCH",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({
      records: [{
        id: recordId,
        fields: { [PDF_ATTACHMENT_COLUMN]: [attachmentId] }
      }]
    })
  });
  if (!patchResponse.ok) {
    throw new Error("Errore durante l'associazione dell'allegato al documento in Grist");
  }
  return privateJsonResponse({
    success: true,
    file: {
      id,
      name,
      size: file.size,
      modifiedTime: new Date().toISOString()
    },
  }, corsHeaders, 201);
}

async function downloadGristPdf(request, env, corsHeaders, fileId) {
  if (!isSessionAuthorized(request, env)) {
    return privateJsonResponse({ success: false, error: "Sessione non autorizzata o scaduta" }, corsHeaders, 403);
  }
  if (typeof fileId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(fileId)) {
    return privateJsonResponse({ success: false, error: "Documento non valido" }, corsHeaders, 400);
  }
  const { documentUrl, headers: gristHeaders } = await ensureGristPdfTable(env);
  const filter = encodeURIComponent(JSON.stringify({ ID: [fileId] }));
  const response = await fetch(
    `${documentUrl}/tables/${encodeURIComponent(PDF_TABLE_ID)}/records?filter=${filter}`,
    { headers: gristHeaders }
  );
  if (!response.ok) {
    throw new Error("Errore durante il recupero del PDF da Grist");
  }
  const data = await response.json();
  const record = (data.records || []).find(item => item.fields?.ID === fileId);
  const attachmentId = record?.fields?.[PDF_ATTACHMENT_COLUMN]?.[0];
  if (!record ||
      record.fields.MimeType !== "application/pdf" ||
      !Number.isSafeInteger(attachmentId) ||
      attachmentId <= 0) {
    return privateJsonResponse({ success: false, error: "Documento non trovato" }, corsHeaders, 404);
  }
  const attachmentResponse = await fetch(
    `${documentUrl}/attachments/${attachmentId}/download`,
    { headers: gristHeaders }
  );
  if (!attachmentResponse.ok || !attachmentResponse.body) {
    throw new Error("Errore durante il recupero dell'allegato PDF da Grist");
  }
  const name = safePdfName(record.fields.Nome);
  const encodedName = encodeURIComponent(name)
    .replace(/['()*]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
  const headers = new Headers(corsHeaders);
  headers.set("Content-Type", "application/pdf");
  headers.set("Content-Disposition", `inline; filename="documento.pdf"; filename*=UTF-8''${encodedName}`);
  headers.set("Cache-Control", "private, no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  const contentLength = attachmentResponse.headers.get("Content-Length");
  if (contentLength) headers.set("Content-Length", contentLength);
  return new Response(attachmentResponse.body, { status: 200, headers });
}

export default {
  async fetch(request, env, ctx) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    if (request.method === "GET" && url.searchParams.get("tipo") === "download_documento_pdf") {
      try {
        return await downloadGristPdf(request, env, corsHeaders, url.searchParams.get("fileId"));
      } catch (error) {
        return privateJsonResponse({ success: false, error: error.message }, corsHeaders, 500);
      }
    }

    if (request.method === "POST") {
      try {
        if (url.searchParams.get("tipo") === "upload_documento_pdf") {
          return await uploadGristPdf(request, env, corsHeaders);
        }
        let body;
        try {
          body = await request.json();
        } catch (e) {
          return new Response(JSON.stringify({ success: false, error: "JSON non valido nel body" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (body.tipo === "auth") {
          if (!env.COMPANY_USERNAME || !env.COMPANY_PASSWORD || !env.GRIST_API_KEY || !env.AUTH_KV) {
            return jsonResponse({ success: false, error: "Configurazione credenziali incompleta sul Worker" }, corsHeaders, 500);
          }
          const username = typeof body.username === "string" ? body.username.trim() : "";
          const validUsername = equalSecret(username, env.COMPANY_USERNAME.trim());
          const validPassword = equalSecret(body.password, env.COMPANY_PASSWORD);
          if (!username || !validUsername || !validPassword) {
            return jsonResponse({ success: false, error: "Nome utente o password non validi" }, corsHeaders, 401);
          }
          await syncPasswordVersion(env, username);
          return issueSession(env, corsHeaders);
        }

        if (body.tipo === "webauthn_auth_options") {
          if (!env.COMPANY_USERNAME || !env.COMPANY_PASSWORD || !env.AUTH_KV) {
            return jsonResponse({ success: false, error: "Configurazione WebAuthn incompleta sul Worker" }, corsHeaders, 500);
          }
          const username = typeof body.username === "string" ? body.username.trim() : "";
          if (!username || !equalSecret(username, env.COMPANY_USERNAME.trim())) {
            return jsonResponse({ success: false, error: "Nome utente non valido" }, corsHeaders, 401);
          }
          await syncPasswordVersion(env, username);
          const credentials = await listCredentials(env, username);
          if (!credentials.length) {
            return jsonResponse({ success: false, error: "Nessuna credenziale biometrica registrata per questo utente" }, corsHeaders, 404);
          }
          const context = getWebAuthnContext(request);
          const challenge = await createWebAuthnChallenge(env, username, "assertion", context);
          const prefix = `credential:${encodeCredentialId(username)}:`;
          return jsonResponse({
            success: true,
            publicKey: {
              challenge,
              timeout: 60000,
              rpId: context.rpId,
              userVerification: "required",
              allowCredentials: credentials.map(key => ({
                type: "public-key",
                id: key.name.slice(prefix.length)
              }))
            }
          }, corsHeaders);
        }

        if (body.tipo === "webauthn_auth_verify") {
          if (!env.COMPANY_USERNAME || !env.COMPANY_PASSWORD || !env.AUTH_KV || !env.GRIST_API_KEY) {
            return jsonResponse({ success: false, error: "Configurazione WebAuthn incompleta sul Worker" }, corsHeaders, 500);
          }
          const username = typeof body.username === "string" ? body.username.trim() : "";
          if (!username || !equalSecret(username, env.COMPANY_USERNAME.trim())) {
            return jsonResponse({ success: false, error: "Nome utente non valido" }, corsHeaders, 401);
          }
          await syncPasswordVersion(env, username);
          const response = body.credential?.response;
          let clientDataJSON;
          let clientData;
          try {
            clientDataJSON = base64UrlDecode(response?.clientDataJSON);
            clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
          } catch (error) {
            return jsonResponse({ success: false, error: "Dati client WebAuthn non validi" }, corsHeaders, 401);
          }
          const challengeRecord = await consumeWebAuthnChallenge(env, clientData.challenge, username, "assertion");
          if (!challengeRecord) {
            return jsonResponse({ success: false, error: "Sfida WebAuthn scaduta o non valida" }, corsHeaders, 401);
          }
          const context = { origin: challengeRecord.origin, rpId: challengeRecord.rpId };
          let credentialId;
          try {
            await verifyClientData(clientDataJSON, "webauthn.get", clientData.challenge, context);
            credentialId = base64UrlEncode(base64UrlDecode(body.credential?.rawId));
            if (body.credential?.type !== "public-key" || credentialId !== body.credential?.id) {
              return jsonResponse({ success: false, error: "Credenziale WebAuthn non valida" }, corsHeaders, 401);
            }
          } catch (error) {
            return jsonResponse({ success: false, error: "Risposta WebAuthn non valida" }, corsHeaders, 401);
          }
          const credentialKey = `credential:${encodeCredentialId(username)}:${credentialId}`;
          const storedCredential = await env.AUTH_KV.get(credentialKey);
          if (!storedCredential) {
            return jsonResponse({ success: false, error: "Credenziale WebAuthn non riconosciuta" }, corsHeaders, 401);
          }
          const credential = JSON.parse(storedCredential);
          let parsedData;
          try {
            const authenticatorData = base64UrlDecode(response.authenticatorData);
            const signature = base64UrlDecode(response.signature);
            parsedData = parseAuthenticatorData(authenticatorData);
            if (!await assertRpIdHash(authenticatorData, context.rpId) ||
                !await verifyAssertionSignature(credential, authenticatorData, clientDataJSON, signature)) {
              return jsonResponse({ success: false, error: "Verifica biometrica non riuscita" }, corsHeaders, 401);
            }
          } catch (error) {
            return jsonResponse({ success: false, error: "Firma WebAuthn non valida" }, corsHeaders, 401);
          }
          if (credential.signCount > 0 && parsedData.signCount <= credential.signCount) {
            return jsonResponse({ success: false, error: "Contatore WebAuthn non valido" }, corsHeaders, 401);
          }
          credential.signCount = parsedData.signCount;
          await env.AUTH_KV.put(credentialKey, JSON.stringify(credential));
          return issueSession(env, corsHeaders);
        }

        const expectedToken = btoa(env.GRIST_API_KEY).substring(0, 30);
        if (!body.token || body.token !== expectedToken) {
          return new Response(JSON.stringify({ success: false, error: "Sessione non autorizzata o scaduta" }), { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "elenco_documenti_pdf") {
          const files = await listGristPdfs(env);
          return privateJsonResponse({ success: true, files }, corsHeaders);
        }

        if (body.tipo === "webauthn_register_options" || body.tipo === "webauthn_register_verify") {
          if (!env.COMPANY_USERNAME || !env.COMPANY_PASSWORD || !env.AUTH_KV) {
            return jsonResponse({ success: false, error: "Configurazione WebAuthn incompleta sul Worker" }, corsHeaders, 500);
          }
          const username = typeof body.username === "string" ? body.username.trim() : "";
          if (!username || !equalSecret(username, env.COMPANY_USERNAME.trim())) {
            return jsonResponse({ success: false, error: "Nome utente non valido" }, corsHeaders, 401);
          }
          await syncPasswordVersion(env, username);
          const context = getWebAuthnContext(request);
          if (body.tipo === "webauthn_register_options") {
            const credentials = await listCredentials(env, username);
            const challenge = await createWebAuthnChallenge(env, username, "registration", context);
            const userId = new Uint8Array(await crypto.subtle.digest("SHA-256", textEncoder.encode(username)));
            const prefix = `credential:${encodeCredentialId(username)}:`;
            return jsonResponse({
              success: true,
              publicKey: {
                challenge,
                rp: { id: context.rpId, name: "Gestionale" },
                user: { id: base64UrlEncode(userId), name: username, displayName: username },
                pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
                timeout: 60000,
                attestation: "none",
                authenticatorSelection: {
                  authenticatorAttachment: "platform",
                  residentKey: "discouraged",
                  userVerification: "required"
                },
                excludeCredentials: credentials.map(key => ({
                  type: "public-key",
                  id: key.name.slice(prefix.length)
                }))
              }
            }, corsHeaders);
          }

          const response = body.credential?.response;
          let clientDataJSON;
          let clientData;
          try {
            clientDataJSON = base64UrlDecode(response?.clientDataJSON);
            clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
          } catch (error) {
            return jsonResponse({ success: false, error: "Dati client WebAuthn non validi" }, corsHeaders, 400);
          }
          const challengeRecord = await consumeWebAuthnChallenge(env, clientData.challenge, username, "registration");
          if (!challengeRecord) {
            return jsonResponse({ success: false, error: "Sfida WebAuthn scaduta o non valida" }, corsHeaders, 401);
          }
          const registrationContext = { origin: challengeRecord.origin, rpId: challengeRecord.rpId };
          let parsedData;
          let publicKey;
          let credentialId;
          try {
            await verifyClientData(clientDataJSON, "webauthn.create", clientData.challenge, registrationContext);
            const attestationObject = decodeCbor(base64UrlDecode(response.attestationObject)).value;
            if (!(attestationObject instanceof Map) ||
                attestationObject.get("fmt") !== "none" ||
                !(attestationObject.get("attStmt") instanceof Map) ||
                attestationObject.get("attStmt").size !== 0 ||
                !(attestationObject.get("authData") instanceof Uint8Array)) {
              return jsonResponse({ success: false, error: "Attestazione WebAuthn non valida" }, corsHeaders, 401);
            }
            const authenticatorData = attestationObject.get("authData");
            if (!await assertRpIdHash(authenticatorData, registrationContext.rpId)) {
              return jsonResponse({ success: false, error: "RP ID WebAuthn non valido" }, corsHeaders, 401);
            }
            parsedData = parseAuthenticatorData(authenticatorData, true);
            credentialId = base64UrlEncode(parsedData.credentialId);
            if (body.credential?.type !== "public-key" ||
                credentialId !== body.credential?.id ||
                credentialId !== base64UrlEncode(base64UrlDecode(body.credential?.rawId))) {
              return jsonResponse({ success: false, error: "ID credenziale WebAuthn non valido" }, corsHeaders, 401);
            }
            publicKey = credentialPublicKey(parsedData.coseKey);
            await crypto.subtle.importKey(
              "jwk",
              publicKey.jwk,
              publicKey.algorithm === -7 ? { name: "ECDSA", namedCurve: "P-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
              false,
              ["verify"]
            );
          } catch (error) {
            return jsonResponse({ success: false, error: `Registrazione WebAuthn non valida: ${error.message}` }, corsHeaders, 400);
          }
          const credentialKey = `credential:${encodeCredentialId(username)}:${credentialId}`;
          if (await env.AUTH_KV.get(credentialKey)) {
            return jsonResponse({ success: false, error: "Questa credenziale è già registrata" }, corsHeaders, 409);
          }
          await env.AUTH_KV.put(credentialKey, JSON.stringify({
            publicKey: publicKey.jwk,
            algorithm: publicKey.algorithm,
            signCount: parsedData.signCount
          }));
          return jsonResponse({ success: true }, corsHeaders);
        }

        const DOC_ID = env.GRIST_DOC_ID;
        const BASE_GRIST = `https://gestionale-lavoro-emanuel-00.getgrist.com/api/docs/${DOC_ID}/tables`;
        const headersGrist = { "Authorization": `Bearer ${env.GRIST_API_KEY}` };

        // ==========================================
        // GESTIONE CONFIGURAZIONI & APP (LETTURA & SCRITTURA)
        // ==========================================

        if (body.tipo === "get_config_app") {
          const res = await fetch(`${BASE_GRIST}/Config_App/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Config_App" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_config_app") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Config_App/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Valore": String(body.valore), "Descrizione": String(body.descrizione) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Config_App" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_parametri_contrattuali") {
          const res = await fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Parametri_contrattuali" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_contrattuali") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Anno_Inizio_Validita": parseInt(body.anno_inizio), "Ferie_Annuo_Spettante": parseFloat(body.ferie_annuo), "Permessi_Annuo_Spettante": parseFloat(body.permessi_annuo) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Parametri_contrattuali" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_contrattuali") {
          const resAdd = await fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Anno_Inizio_Validita": parseInt(body.anno_inizio), "Ferie_Annuo_Spettante": parseFloat(body.ferie_annuo), "Permessi_Annuo_Spettante": parseFloat(body.permessi_annuo) } }] })
          });
          if (!resAdd.ok) return new Response(JSON.stringify({ success: false, error: "Errore aggiunta Parametri_contrattuali" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_tipi_assenza") {
          const res = await fetch(`${BASE_GRIST}/Tipi_Assenza/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Tipi_Assenza" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_tipo_assenza") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Tipi_Assenza/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Nome": String(body.nome), "Blocca_Timbrature": Boolean(body.blocca), "Attivo": Boolean(body.attivo) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Tipi_Assenza" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_tipo_assenza") {
          const nome = String(body.nome || "").trim();
          if (!nome) return new Response(JSON.stringify({ success: false, error: "Nome assenza non valido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const resAdd = await fetch(`${BASE_GRIST}/Tipi_Assenza/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Nome": nome, "Blocca_Timbrature": Boolean(body.blocca), "Attivo": Boolean(body.attivo) } }] })
          });
          if (!resAdd.ok) return new Response(JSON.stringify({ success: false, error: "Errore aggiunta Tipi_Assenza" }), { status: resAdd.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_tipi_timbratura") {
          const res = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Tipi_Timbratura" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_tipo_timbratura") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Nome": String(body.nome), "Unico_Al_Giorno": Boolean(body.unico), "Attivo": Boolean(body.attivo), "Ordine": parseInt(body.ordine) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Tipi_Timbratura" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_tipo_timbratura") {
          const nome = String(body.nome || "").trim();
          const ordine = Number.parseInt(body.ordine, 10);
          if (!nome || !Number.isInteger(ordine)) return new Response(JSON.stringify({ success: false, error: "Nome o ordine timbratura non valido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const resAdd = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Nome": nome, "Unico_Al_Giorno": Boolean(body.unico), "Attivo": Boolean(body.attivo), "Ordine": ordine } }] })
          });
          if (!resAdd.ok) return new Response(JSON.stringify({ success: false, error: "Errore aggiunta Tipi_Timbratura" }), { status: resAdd.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_avvisi") {
          const res = await fetch(`${BASE_GRIST}/Avvisi/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Avvisi" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_avviso") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Avvisi/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Titolo": String(body.titolo), "Messaggio": String(body.messaggio), "Tipo": String(body.tipo_avviso), "Data_Scadenza": Number(body.data_scadenza) || null, "Attivo": Boolean(body.attivo) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Avvisi" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // ==========================================
        // ENDPOINT ESISTENTI (INVARIATI)
        // ==========================================

        if (body.tipo === "get_presenze") {
          const [giorno, mese, anno] = body.data.split('/').map(Number);
          const timestampGristEpoch = Math.floor(Date.UTC(anno, mese - 1, giorno, 0, 0, 0) / 1000);
          const filtroGrist = encodeURIComponent(JSON.stringify({ Data: [timestampGristEpoch] }));
          const responseGrist = await fetch(`${BASE_GRIST}/Prova/records?filter=${filtroGrist}`, { headers: headersGrist });
          if (!responseGrist.ok) {
            return new Response(JSON.stringify({ success: false, error: "Errore recupero Grist" }), { status: responseGrist.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const datiGrist = await responseGrist.json();
          const records = datiGrist.records || [];
          const eventosRegistrati = records.map(r => r.fields.Evento);
          return new Response(JSON.stringify({ success: true, eventi: eventosRegistrati, records: records }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "check_assenza") {
          const [giorno, mese, anno] = body.data.split('/').map(Number);
          const epochInizio = Math.floor(Date.UTC(anno, mese - 1, giorno, 0, 0, 0) / 1000);
          const epochFine = Math.floor(Date.UTC(anno, mese - 1, giorno, 23, 59, 59) / 1000);
          
          const [resReg, resTipi] = await Promise.all([
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Tipi_Assenza/records`, { headers: headersGrist })
          ]);
          
          if (!resReg.ok || !resTipi.ok) {
            return new Response(JSON.stringify({ success: false, error: "Errore verifica assenze su Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          
          const datiReg = await resReg.json();
          const datiTipi = await resTipi.json();
          
          const mappaBlocco = {};
          (datiTipi.records || []).forEach(t => {
            if (t.fields.Nome) {
              mappaBlocco[t.fields.Nome.trim().toLowerCase()] = Boolean(t.fields.Blocca_Timbrature);
            }
          });

          const idRigaDaIgnorare = body.id_riga == null ? null : Number(body.id_riga);
          const assenzeDelGiorno = (datiReg.records || []).filter(r =>
            r.fields.Data >= epochInizio &&
            r.fields.Data <= epochFine &&
            (idRigaDaIgnorare === null || r.id !== idRigaDaIgnorare)
          );
          const esisteAssenza = assenzeDelGiorno.length > 0;
          const bloccaTimbrature = assenzeDelGiorno.some(r => {
            const nomeTipo = String(r.fields.Tipo_Assenza || "").trim().toLowerCase();
            return mappaBlocco[nomeTipo] === true;
          });

          return new Response(JSON.stringify({ success: true, esiste: esisteAssenza, bloccaTimbrature: bloccaTimbrature }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_report_annuale") {
          const isTutti = (body.anno === "TUTTI");
          const anno_rif = isTutti ? null : parseInt(body.anno);
          if (!isTutti && !anno_rif) return new Response(JSON.stringify({ success: false, error: "Anno non specificato" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

          const [resParametri, resContatori, resAssenze] = await Promise.all([
            fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Contatori/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist })
          ]);
          if (!resParametri.ok || !resContatori.ok || !resAssenze.ok) {
            return new Response(JSON.stringify({ success: false, error: "Impossibile recuperare i dati da Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          const [parametriData, contatoriData, assenzeData] = await Promise.all([resParametri.json(), resContatori.json(), resAssenze.json()]);

          const getDatiContrattoAnno = (targetAnno) => {
            let f_anno = 25.92, p_anno = 40.0, u_valido = 0;
            for (const config of (parametriData.records || [])) {
              const conf_anno = parseInt(config.fields.Anno_Inizio_Validita || 0);
              if (conf_anno <= targetAnno && conf_anno > u_valido) {
                f_anno = parseFloat(config.fields.Ferie_Annuo_Spettante || 25.92);
                p_anno = parseFloat(config.fields.Permessi_Annuo_Spettante || 40.0);
                u_valido = conf_anno;
              }
            }
            for (const c of (contatoriData.records || [])) {
              if (parseInt(c.fields.Anno || 0) === targetAnno) {
                if (c.fields.Ferie_Annuali_Maturate) f_anno = parseFloat(c.fields.Ferie_Annuali_Maturate);
                if (c.fields.Permessi_Annuali_Maturati) p_anno = parseFloat(c.fields.Permessi_Annuali_Maturati);
                break;
              }
            }
            return { f_anno, p_anno };
          };

          if (isTutti) {
            const anniTrovati = new Set();
            (assenzeData.records || []).forEach(r => { if (r.fields.Data) anniTrovati.add(new Date(r.fields.Data * 1000).getUTCFullYear()); });
            (contatoriData.records || []).forEach(c => { if (c.fields.Anno) anniTrovati.add(parseInt(c.fields.Anno)); });
            if (anniTrovati.size === 0) anniTrovati.add(new Date().getFullYear());

            let tot_f_mat = 0, tot_p_mat = 0;
            anniTrovati.forEach(a => { const d = getDatiContrattoAnno(a); tot_f_mat += d.f_anno; tot_p_mat += d.p_anno; });

            let f_god = 0, f_liq = 0, f_ret = 0, p_god = 0, p_liq = 0, p_ret = 0, malattia_tot = 0;
            for (const r of (assenzeData.records || [])) {
              if (!r.fields.Data) continue;
              const tipo = String(r.fields.Tipo_Assenza || "").toLowerCase().trim();
              const qta = parseFloat(String(r.fields.Quantita || 0).replace(",", ".").trim()) || 0;
              if (tipo.includes("ferie")) {
                if (tipo.includes("liquidat")) f_liq += qta;
                else if (tipo.includes("rettific")) f_ret += qta;
                else f_god += qta;
              } else if (tipo.includes("permess")) {
                if (tipo.includes("liquidat")) p_liq += qta;
                else if (tipo.includes("rettific")) p_ret += qta;
                else p_god += qta;
              } else if (tipo.includes("malattia")) malattia_tot += qta;
            }

            let testoReport = `========================================\n RIEPILOGO STORICO ANNUALE (TUTTI GLI ANNI: ${Array.from(anniTrovati).sort().join(', ')})\n========================================\n\n`;
            testoReport += `MOVIMENTI FERIE CUMULATI\n----------------------------------------\n`;
            testoReport += ` [+] Ferie maturate (somma anni) : +${Math.round(tot_f_mat * 100) / 100} giorni\n`;
            testoReport += ` [-] Ferie godute (vacanze reali) : -${Math.round(f_god * 100) / 100} giorni\n`;
            if (f_liq > 0.01) testoReport += ` [-] Ferie liquidate/pagate     : -${Math.round(f_liq * 100) / 100} giorni\n`;
            if (f_ret > 0.01) testoReport += ` [+/-] Rettifiche ferie (storni): +${Math.round(f_ret * 100) / 100} giorni\n\n\n`;
            testoReport += `MOVIMENTI PERMESSI CUMULATI\n----------------------------------------\n`;
            testoReport += ` [+] Permessi maturati (somma anni) : +${Math.round(tot_p_mat * 100) / 100} ore\n`;
            testoReport += ` [-] Permessi fruiti (ore assenza) : -${Math.round(p_god * 100) / 100} ore\n`;
            if (p_liq > 0.01) testoReport += ` [-] Permessi liquidati/pagate  : -${Math.round(p_liq * 100) / 100} ore\n`;
            if (p_ret > 0.01) testoReport += ` [+/-] Rettifiche permessi (storni): +${Math.round(p_ret * 100) / 100} ore\n\n\n`;
            testoReport += `MALATTIE CUMULATE\n----------------------------------------\n * Giorni di malattia totali    : ${Math.round(malattia_tot * 100) / 100} giorni\n========================================`;

            return new Response(JSON.stringify({ success: true, testoReport, anno: "Tutti_gli_Anni" }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          let { f_anno: ferie_contratto_anno, p_anno: permessi_contratto_anno } = getDatiContrattoAnno(anno_rif);
          let partenza_ferie = 0.0, partenza_permessi = 0.0;
          for (const c of (contatoriData.records || [])) {
            if (parseInt(c.fields.Anno || 0) === anno_rif) {
              partenza_ferie = parseFloat(c.fields.Ferie_Anno_Precedente || 0);
              partenza_permessi = parseFloat(c.fields.Permessi_Anno_Precedente || 0);
              break;
            }
          }

          let f_god = 0, f_liq = 0, f_ret = 0, p_god = 0, p_liq = 0, p_ret = 0, malattia_anno = 0;
          for (const r of (assenzeData.records || [])) {
            if (!r.fields.Data) continue;
            if (new Date(r.fields.Data * 1000).getUTCFullYear() === anno_rif) {
              const tipo = String(r.fields.Tipo_Assenza || "").toLowerCase().trim();
              const qta = parseFloat(String(r.fields.Quantita || 0).replace(",", ".").trim()) || 0;
              if (tipo.includes("ferie")) {
                if (tipo.includes("liquidat")) f_liq += qta;
                else if (tipo.includes("rettific")) f_ret += qta;
                else f_god += qta;
              } else if (tipo.includes("permess")) {
                if (tipo.includes("liquidat")) p_liq += qta;
                else if (tipo.includes("rettific")) p_ret += qta;
                else p_god += qta;
              } else if (tipo.includes("malattia")) malattia_anno += qta;
            }
          }

          const saldo_ferie = Math.round((partenza_ferie + ferie_contratto_anno - f_god - f_liq + f_ret) * 100) / 100;
          const saldo_permessi = Math.round((partenza_permessi + permessi_contratto_anno - p_god - p_liq + p_ret) * 100) / 100;

          let testoReport = `========================================\n RIEPILOGO ANNUALE COMPLESSIVO: ANNO ${anno_rif}\n========================================\n\n`;
          testoReport += `MOVIMENTI FERIE DELL'ANNO\n----------------------------------------\n`;
          testoReport += ` <<< Residuo anno precedente    : ${partenza_ferie} giorni\n`;
          testoReport += ` [+] Ferie maturate nell'anno   : +${ferie_contratto_anno} giorni\n`;
          testoReport += ` [-] Ferie godute (vacanze reali) : -${Math.round(f_god * 100) / 100} giorni\n`;
          if (f_liq > 0.01) testoReport += ` [-] Ferie liquidate/pagate     : -${Math.round(f_liq * 100) / 100} giorni\n`;
          if (f_ret > 0.01) testoReport += ` [+/-] Rettifiche ferie (storni): +${Math.round(f_ret * 100) / 100} giorni\n`;
          testoReport += `\n >>> SALDO FERIE A FINE ANNO    : ${saldo_ferie} giorni\n\n\n`;
          testoReport += `MOVIMENTI PERMESSI DELL'ANNO\n----------------------------------------\n`;
          testoReport += ` <<< Residuo anno precedente    : ${partenza_permessi} ore\n`;
          testoReport += ` [+] Permessi maturati nell'anno: +${permessi_contratto_anno} ore\n`;
          testoReport += ` [-] Permessi fruiti (ore assenza) : -${Math.round(p_god * 100) / 100} ore\n`;
          if (p_liq > 0.01) testoReport += ` [-] Permessi liquidati/pagati  : -${Math.round(p_liq * 100) / 100} ore\n`;
          if (p_ret > 0.01) testoReport += ` [+/-] Rettifiche permessi (storni): +${Math.round(p_ret * 100) / 100} ore\n`;
          testoReport += `\n >>> SALDO PERMESSI A FINE ANNO : ${saldo_permessi} ore\n\n\n`;
          testoReport += `MALATTIE DELL'ANNO\n----------------------------------------\n * Giorni di malattia nell'anno : ${Math.round(malattia_anno * 100) / 100} giorni\n========================================`;

          return new Response(JSON.stringify({ success: true, testoReport, anno: anno_rif }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "genera_report_mensile") {
          const { anno, mese } = body;
          const mesi_mappatura = { "Gennaio": 1, "Febbraio": 2, "Marzo": 3, "Aprile": 4, "Maggio": 5, "Giugno": 6, "Luglio": 7, "Agosto": 8, "Settembre": 9, "Ottobre": 10, "Novembre": 11, "Dicembre": 12 };
          const mese_rif = mesi_mappatura[mese];
          if (!anno || !mese_rif) return new Response(JSON.stringify({ success: false, error: "Anno o Mese non valido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

          const [resParametri, resContatori, resAssenze] = await Promise.all([
            fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Contatori/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist })
          ]);
          if (!resParametri.ok || !resContatori.ok || !resAssenze.ok) {
            return new Response(JSON.stringify({ success: false, error: "Impossibile recuperare i registri da Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          const [parametriData, contatoriData, assenzeData] = await Promise.all([resParametri.json(), resContatori.json(), resAssenze.json()]);

          const getParametriPerAnno = (targetAnno) => {
            let f_anno = 25.92, p_anno = 40.0, u_valido = 0;
            for (const config of (parametriData.records || [])) {
              const conf_anno = parseInt(config.fields.Anno_Inizio_Validita || 0);
              if (conf_anno <= targetAnno && conf_anno > u_valido) {
                f_anno = parseFloat(config.fields.Ferie_Annuo_Spettante || 25.92);
                p_anno = parseFloat(config.fields.Permessi_Annuo_Spettante || 40.0);
                u_valido = conf_anno;
              }
            }
            return { coeffFerie: Math.round((f_anno / 12) * 100) / 100, coeffPermessi: Math.round((p_anno / 12) * 100) / 100 };
          };

          if (anno === "TUTTI") {
            const anniTrovati = new Set();
            (assenzeData.records || []).forEach(r => { if (r.fields.Data) anniTrovati.add(new Date(r.fields.Data * 1000).getUTCFullYear()); });
            (contatoriData.records || []).forEach(c => { if (c.fields.Anno) anniTrovati.add(parseInt(c.fields.Anno)); });
            if (anniTrovati.size === 0) anniTrovati.add(new Date().getFullYear());

            let tot_mat_ferie = 0, tot_mat_permessi = 0;
            anniTrovati.forEach(a => { const p = getParametriPerAnno(a); tot_mat_ferie += p.coeffFerie; tot_mat_permessi += p.coeffPermessi; });

            let f_god = 0, f_liq = 0, f_ret = 0, p_god = 0, p_liq = 0, p_ret = 0, mal_tot = 0;
            for (const r of (assenzeData.records || [])) {
              if (!r.fields.Data) continue;
              if ((new Date(r.fields.Data * 1000).getUTCMonth() + 1) === mese_rif) {
                const tipo = String(r.fields.Tipo_Assenza || "").toLowerCase().trim();
                const qta = parseFloat(String(r.fields.Quantita || 0).replace(",", ".").trim()) || 0;
                if (tipo.includes("ferie")) {
                  if (tipo.includes("liquidat")) f_liq += qta;
                  else if (tipo.includes("rettific")) f_ret += qta;
                  else f_god += qta;
                } else if (tipo.includes("permess")) {
                  if (tipo.includes("liquidat")) p_liq += qta;
                  else if (tipo.includes("rettific")) p_ret += qta;
                  else p_god += qta;
                } else if (tipo.includes("malattia")) mal_tot += qta;
              }
            }

            let testoReport = `========================================\n RIEPILOGO STORICO MESE DI ${mese.toUpperCase()} (TUTTI GLI ANNI: ${Array.from(anniTrovati).sort().join(', ')})\n========================================\n\n`;
            testoReport += `MOVIMENTI FERIE DI QUESTO MESE\n----------------------------------------\n`;
            testoReport += ` [+] Ferie maturate (somma anni) : +${Math.round(tot_mat_ferie * 100) / 100} giorni\n`;
            testoReport += ` [-] Ferie godute (vacanze reali) : -${Math.round(f_god * 100) / 100} giorni\n`;
            if (f_liq > 0.01) testoReport += ` [-] Ferie liquidate/pagate     : -${Math.round(f_liq * 100) / 100} giorni\n`;
            if (f_ret > 0.01) testoReport += ` [+/-] Rettifiche ferie (storni): +${Math.round(f_ret * 100) / 100} giorni\n\n\n`;
            testoReport += `MOVIMENTI PERMESSI DI QUESTO MESE\n----------------------------------------\n`;
            testoReport += ` [+] Permessi maturati (somma anni) : +${Math.round(tot_mat_permessi * 100) / 100} ore\n`;
            testoReport += ` [-] Permessi fatti (ore assenza) : -${Math.round(p_god * 100) / 100} ore\n`;
            if (p_liq > 0.01) testoReport += ` [-] Permessi liquidati/pagati  : -${Math.round(p_liq * 100) / 100} ore\n`;
            if (p_ret > 0.01) testoReport += ` [+/-] Rettifiche permessi (storni): +${Math.round(p_ret * 100) / 100} ore\n\n\n`;
            testoReport += `MALATTIE DEL MESE\n----------------------------------------\n * Giorni di malattia nel mese  : ${Math.round(mal_tot * 100) / 100} giorni\n========================================`;

            return new Response(JSON.stringify({ success: true, testoReport, mese, anno: "Tutti_gli_Anni" }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          const anno_rif = parseInt(anno);
          const { coeffFerie: coeff_ferie_mese, coeffPermessi: coeff_permessi_mese } = getParametriPerAnno(anno_rif);

          let partenza_ferie = 0.0, partenza_permessi = 0.0;
          for (const c of (contatoriData.records || [])) {
            if (parseInt(c.fields.Anno || 0) === anno_rif) {
              partenza_ferie = parseFloat(c.fields.Ferie_Anno_Precedente || 0);
              partenza_permessi = parseFloat(c.fields.Permessi_Anno_Precedente || 0);
              break;
            }
          }

          let ferie_godute_mese = 0, ferie_liquidate_mese = 0, ferie_rettificate_mese = 0;
          let permessi_fatti_mese = 0, permessi_liquidati_mese = 0, permessi_rettificati_mese = 0, malattia_mese = 0;
          let ferie_cumulate_fino_a_mese = 0, permessi_cumulati_fino_a_mese = 0;
          let ferie_cumulate_mese_precedente = 0, permessi_cumulati_mese_precedente = 0;

          for (const r of (assenzeData.records || [])) {
            if (!r.fields.Data) continue;
            const dataRecord = new Date(r.fields.Data * 1000);
            if (dataRecord.getUTCFullYear() === anno_rif) {
              const tipo = String(r.fields.Tipo_Assenza || "").toLowerCase().trim();
              const qta = parseFloat(String(r.fields.Quantita || 0).replace(",", ".").trim()) || 0;
              const meseRecord = dataRecord.getUTCMonth() + 1;

              if (meseRecord <= mese_rif) {
                if (tipo.includes("ferie")) ferie_cumulate_fino_a_mese += tipo.includes("rettific") ? -qta : qta;
                else if (tipo.includes("permess")) permessi_cumulati_fino_a_mese += tipo.includes("rettific") ? -qta : qta;
              }
              if (meseRecord < mese_rif) {
                if (tipo.includes("ferie")) ferie_cumulate_mese_precedente += tipo.includes("rettific") ? -qta : qta;
                else if (tipo.includes("permess")) permessi_cumulati_mese_precedente += tipo.includes("rettific") ? -qta : qta;
              }
              if (meseRecord === mese_rif) {
                if (tipo.includes("ferie")) {
                  if (tipo.includes("liquidat")) ferie_liquidate_mese += qta;
                  else if (tipo.includes("rettific")) ferie_rettificate_mese += qta;
                  else ferie_godute_mese += qta;
                } else if (tipo.includes("permess")) {
                  if (tipo.includes("liquidat")) permessi_liquidati_mese += qta;
                  else if (tipo.includes("rettific")) permessi_rettificati_mese += qta;
                  else permessi_fatti_mese += qta;
                } else if (tipo.includes("malattia")) malattia_mese += qta;
              }
            }
          }

          const mesi_precedenti_contati = mese_rif - 1;
          const saldo_precedente_ferie = Math.round((partenza_ferie + (coeff_ferie_mese * mesi_precedenti_contati) - ferie_cumulate_mese_precedente) * 100) / 100;
          const saldo_precedente_permessi = Math.round((partenza_permessi + (coeff_permessi_mese * mesi_precedenti_contati) - permessi_cumulati_mese_precedente) * 100) / 100;
          const saldo_reale_ferie_mese = Math.round((partenza_ferie + (coeff_ferie_mese * mese_rif) - ferie_cumulate_fino_a_mese) * 100) / 100;
          const saldo_reale_permessi_mese = Math.round((partenza_permessi + (coeff_permessi_mese * mese_rif) - permessi_cumulati_fino_a_mese) * 100) / 100;

          let testoReport = `========================================\n RIEPILOGO MENSILE: ${mese.toUpperCase()} ${anno_rif}\n========================================\n\n`;
          testoReport += `MOVIMENTI FERIE DI QUESTO MESE\n----------------------------------------\n`;
          testoReport += ` <<< SALDO MESE PRECEDENTE      : ${saldo_precedente_ferie} giorni\n`;
          testoReport += ` [+] Ferie maturate nel mese    : +${coeff_ferie_mese} giorni\n`;
          testoReport += ` [-] Ferie godute (vacanze reali) : -${Math.round(ferie_godute_mese * 100) / 100} giorni\n`;
          if (ferie_liquidate_mese > 0.01) testoReport += ` [-] Ferie liquidate/pagate     : -${Math.round(ferie_liquidate_mese * 100) / 100} giorni\n`;
          if (ferie_rettificate_mese > 0.01) testoReport += ` [+/-] Rettifiche ferie del mese: (Stornati ${Math.round(ferie_rettificate_mese * 100) / 100} gg)\n`;
          testoReport += `\n >>> SALDO FERIE A FINE MESE    : ${saldo_reale_ferie_mese} giorni\n\n\n`;
          testoReport += `MOVIMENTI PERMESSI DI QUESTO MESE\n----------------------------------------\n`;
          testoReport += ` <<< SALDO MESE PRECEDENTE      : ${saldo_precedente_permessi} ore\n`;
          testoReport += ` [+] Permessi maturati nel mese : +${coeff_permessi_mese} ore\n`;
          testoReport += ` [-] Permessi fatti (ore assenza) : -${Math.round(permessi_fatti_mese * 100) / 100} ore\n`;
          if (permessi_liquidati_mese > 0.01) testoReport += ` [-] Permessi liquidati/pagati  : -${Math.round(permessi_liquidati_mese * 100) / 100} ore\n`;
          if (permessi_rettificati_mese > 0.01) testoReport += ` [+/-] Rettifiche permessi mese : (Stornate ${Math.round(permessi_rettificati_mese * 100) / 100} ore)\n`;
          testoReport += `\n >>> SALDO PERMESSI A FINE MESE : ${saldo_reale_permessi_mese} ore\n\n\n`;
          testoReport += `MALATTIE DEL MESE\n----------------------------------------\n * Giorni di malattia nel mese  : ${Math.round(malattia_mese * 100) / 100} giorni\n========================================`;

          return new Response(JSON.stringify({ success: true, message: "Report calcolato", testoReport, mese, anno: anno_rif }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "genera_report_timbrature_mensile" || body.tipo === "get_report_timbrature_annuale") {
          const isMensile = (body.tipo === "genera_report_timbrature_mensile");
          const { anno, mese } = body;
          const isTutti = (anno === "TUTTI");
          const anno_rif = isTutti ? null : parseInt(anno);

          const mesi_mappatura = { "Gennaio": 1, "Febbraio": 2, "Marzo": 3, "Aprile": 4, "Maggio": 5, "Giugno": 6, "Luglio": 7, "Agosto": 8, "Settembre": 9, "Ottobre": 10, "Novembre": 11, "Dicembre": 12 };
          const mese_rif = isMensile ? mesi_mappatura[mese] : null;

          if ((!isTutti && !anno_rif) || (isMensile && !mese_rif)) {
            return new Response(JSON.stringify({ success: false, error: "Parametri Anno o Mese non validi" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          const resPresenze = await fetch(`${BASE_GRIST}/Prova/records`, { headers: headersGrist });
          if (!resPresenze.ok) {
            return new Response(JSON.stringify({ success: false, error: "Impossibile recuperare le timbrature da Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const presenzeData = await resPresenze.json();

          const giorniMap = {};
          const anniTrovati = new Set();

          for (const r of (presenzeData.records || [])) {
            if (!r.fields || !r.fields.Data) continue;
            const d = new Date(r.fields.Data * 1000);
            const y = d.getUTCFullYear();
            const m = d.getUTCMonth() + 1;
            const g = d.getUTCDate();

            if (!isTutti && y !== anno_rif) continue;
            if (isMensile && m !== mese_rif) continue;

            anniTrovati.add(y);
            const key = `${y}-${String(m).padStart(2, '0')}-${String(g).padStart(2, '0')}`;
            if (!giorniMap[key]) giorniMap[key] = {};

            const ora = parseInt(r.fields.Ora || 0);
            const min = parseInt(r.fields.Minuti || 0);
            giorniMap[key][r.fields.Evento] = (ora * 60) + min;
          }

          let giorniLavorati = 0;
          let giorniCantiere = 0;
          let giorniIncompleti = 0;
          let minutiLavoratiTotali = 0;
          let minutiPausaTotali = 0;
          let minutiStraordinarioTotali = 0;

          Object.values(giorniMap).forEach(ev => {
            if (ev["Cantiere"] !== undefined && ev["Ingresso"] === undefined) {
              giorniCantiere++;
              return;
            }
            if (ev["Ingresso"] !== undefined && ev["Uscita"] !== undefined) {
              giorniLavorati++;
              let lordi = ev["Uscita"] - ev["Ingresso"];
              if (lordi < 0) lordi = 0;

              let pausa = 0;
              if (ev["Inizio Pausa"] !== undefined && ev["Fine Pausa"] !== undefined) {
                pausa = Math.max(0, ev["Fine Pausa"] - ev["Inizio Pausa"]);
              } else if (lordi > 360) {
                pausa = 60;
              }

              const netti = Math.max(0, lordi - pausa);
              minutiLavoratiTotali += netti;
              minutiPausaTotali += pausa;
              if (netti > 480) {
                minutiStraordinarioTotali += (netti - 480);
              }
            } else if (ev["Ingresso"] !== undefined || ev["Uscita"] !== undefined) {
              giorniIncompleti++;
            }
          });

          const formatOre = (minutiTot) => {
            const h = Math.floor(minutiTot / 60);
            const m = Math.round(minutiTot % 60);
            return `${h} ore e ${String(m).padStart(2, '0')} min (${(minutiTot / 60).toFixed(2)} h)`;
          };

          const titoloPeriodo = isMensile
            ? (isTutti ? `${mese.toUpperCase()} (TUTTI GLI ANNI: ${Array.from(anniTrovati).sort().join(', ')})` : `${mese.toUpperCase()} ${anno_rif}`)
            : (isTutti ? `TUTTI GLI ANNI (${Array.from(anniTrovati).sort().join(', ')})` : `ANNO ${anno_rif}`);

          let testoReport = `========================================\n RIEPILOGO TIMBRATURE: ${titoloPeriodo}\n========================================\n\n`;
          testoReport += `PRESENZE E GIORNATE\n----------------------------------------\n`;
          testoReport += ` [+] Giorni lavorati completi   : ${giorniLavorati} giorni\n`;
          if (giorniCantiere > 0) testoReport += ` [+] Giornate solo Cantiere     : ${giorniCantiere} giorni\n`;
          if (giorniIncompleti > 0) testoReport += ` [+/-] Giornate incomplete      : ${giorniIncompleti} giorni\n`;
          testoReport += `\n >>> TOTALE GIORNI REGISTRATI   : ${giorniLavorati + giorniCantiere} giorni\n\n\n`;

          testoReport += `CONTEGGIO ORE LAVORATE\n----------------------------------------\n`;
          testoReport += ` [+] Ore nette lavorate totali  : ${formatOre(minutiLavoratiTotali)}\n`;
          testoReport += ` [-] Ore pausa pranzo detratte  : ${formatOre(minutiPausaTotali)}\n`;
          testoReport += ` [+] Ore straordinario (>8h/gg) : ${formatOre(minutiStraordinarioTotali)}\n`;
          testoReport += `\n >>> TOTALE ORE NETTE PERIODO   : ${(minutiLavoratiTotali / 60).toFixed(2)} ore\n========================================`;

          return new Response(JSON.stringify({
            success: true,
            testoReport,
            mese: isMensile ? mese : null,
            anno: isTutti ? "Tutti_gli_Anni" : anno_rif
          }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_verifica_buste_paga") {
          const response = await fetch(`${BASE_GRIST}/Verifica_Buste_Paga/records`, { headers: headersGrist });
          if (!response.ok) {
            return new Response(JSON.stringify({ success: false, error: "Errore recupero Verifica_Buste_Paga" }), { status: response.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const data = await response.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "salva_verifica_busta_paga") {
          const ferieInput = body.ferie_residue;
          const permessiInput = body.permessi_residui;
          const anno = Number(body.anno);
          const mese = Number(body.mese);
          const ferieResidue = Number(ferieInput);
          const permessiResidui = Number(permessiInput);
          if (!Number.isInteger(anno) || anno < 1900 || anno > 9999 ||
              !Number.isInteger(mese) || mese < 1 || mese > 12 ||
              ferieInput === undefined || ferieInput === null || ferieInput === "" ||
              permessiInput === undefined || permessiInput === null || permessiInput === "" ||
              !Number.isFinite(ferieResidue) || !Number.isFinite(permessiResidui)) {
            return new Response(JSON.stringify({ success: false, error: "Dati della verifica busta paga non validi" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const fields = {
            "Anno": anno,
            "Mese": mese,
            "Ferie_Residuo_BustaPaga": ferieResidue,
            "Permessi_Residuo_BustaPaga": permessiResidui
          };
          const response = await fetch(`${BASE_GRIST}/Verifica_Buste_Paga/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({
              records: [{ id: 1, fields }]
            })
          });
          if (!response.ok) {
            return new Response(JSON.stringify({ success: false, error: "Errore aggiornamento della riga ID 1 in Verifica_Buste_Paga" }), { status: response.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const data = (await response.json()) || {};
          const records = Array.isArray(data.records) ? data.records : [];
          return new Response(JSON.stringify({ success: true, records }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_dashboard_data") {
          const [resPresenze, resAssenze, resContatori, resParametri] = await Promise.all([
            fetch(`${BASE_GRIST}/Prova/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Contatori/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, { headers: headersGrist })
          ]);
          if (!resPresenze.ok || !resAssenze.ok || !resContatori.ok || !resParametri.ok) {
            return new Response(JSON.stringify({ success: false, error: "Impossibile recuperare i dati della dashboard da Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const [presenzeData, assenzeData, contatoriData, parametriData] = await Promise.all([
            resPresenze.json(), resAssenze.json(), resContatori.json(), resParametri.json()
          ]);
          return new Response(JSON.stringify({
            success: true,
            presenze: presenzeData.records || [],
            assenze: assenzeData.records || [],
            contatori: contatoriData.records || [],
            parametri: parametriData.records || []
          }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_storico") {
          const annoFiltro = String(body.anno || new Date().getFullYear());
          const [resPresenze, resAssenze] = await Promise.all([
            fetch(`${BASE_GRIST}/Prova/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist })
          ]);
          if (!resPresenze.ok || !resAssenze.ok) {
            return new Response(JSON.stringify({ success: false, error: "Errore API Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const [presenzeData, assenzeData] = await Promise.all([resPresenze.json(), resAssenze.json()]);

          const getTimestamp = (val) => {
            if (!val) return 0;
            if (typeof val === 'number') return val * 1000;
            if (typeof val === 'string' && val.includes('/')) {
              const [gg, mm, aa] = val.split('/');
              const d = new Date(`${aa}-${mm.padStart(2, '0')}-${gg.padStart(2, '0')}T00:00:00Z`);
              return isNaN(d.getTime()) ? 0 : d.getTime();
            }
            const d = new Date(val);
            return isNaN(d.getTime()) ? 0 : d.getTime();
          };

          const filtraEOrdina = (records) => (records || [])
            .filter(r => r.fields && r.fields.Data && getTimestamp(r.fields.Data) !== 0 && new Date(getTimestamp(r.fields.Data)).getUTCFullYear().toString() === annoFiltro)
            .sort((a, b) => getTimestamp(b.fields.Data) - getTimestamp(a.fields.Data));

          return new Response(JSON.stringify({
            success: true,
            presenze: filtraEOrdina(presenzeData.records),
            assenze: filtraEOrdina(assenzeData.records)
          }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "elimina_record") {
          const tabelleEliminabili = {
            presenze: "Prova",
            assenze: "Registro_Ferie_Permessi",
            registro: "Registro_Ferie_Permessi",
            parametri_contrattuali: "Parametri_contrattuali",
            tipi_timbratura: "Tipi_Timbratura",
            tipi_assenza: "Tipi_Assenza",
            verifica_buste_paga: "Verifica_Buste_Paga"
          };
          const tabellaId = Object.hasOwn(tabelleEliminabili, body.tabella) ? tabelleEliminabili[body.tabella] : null;
          const idRecord = Number(body.id_riga);
          if (!tabellaId || !Number.isSafeInteger(idRecord) || idRecord <= 0) return new Response(JSON.stringify({ success: false, error: "Tabella o ID record non valido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

          const resElimina = await fetch(`${BASE_GRIST}/${tabellaId}/records/delete`, {
            method: "POST", headers: { ...headersGrist, "Content-Type": "application/json" },
            body: JSON.stringify([idRecord])
          });
          if (!resElimina.ok) return new Response(JSON.stringify({ success: false, error: "Errore durante l'eliminazione su Grist" }), { status: resElimina.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        let tabellaId = "";
        let fields = {};
        const idRigaModifica = body.id_riga;

        if (body.tipo === "presenze") {
          tabellaId = "Prova";
          fields = {
            "Data": body.data,
            "Evento": body.evento,
            "Ora": String(body.ore || 0).padStart(2, '0'),
            "Minuti": String(body.minuti || 0).padStart(2, '0'),
            "Note": body.note
          };
        } else if (body.tipo === "registro") {
          tabellaId = "Registro_Ferie_Permessi";
          fields = {
            "Data": body.data,
            "Tipo_Assenza": body.tipoAssenza,
            "Quantita": body.quantita,
            "Note": body.note
          };
        } else {
          return new Response(JSON.stringify({ success: false, error: "Tipo richiesta non riconosciuto" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (idRigaModifica) {
          fields["Ultima_Modifica"] = Math.floor(Date.now() / 1000);
          fields["Note_Modifica"] = body.note_modifica || "Modificato da pannello gestionale";
        }

        const metodoHTTP = idRigaModifica ? "PATCH" : "POST";
        const payloadGrist = idRigaModifica
          ? { records: [{ id: parseInt(idRigaModifica), fields }] }
          : { records: [{ fields }] };

        const response = await fetch(`${BASE_GRIST}/${tabellaId}/records`, {
          method: metodoHTTP,
          headers: { "Content-Type": "application/json", ...headersGrist },
          body: JSON.stringify(payloadGrist)
        });

        const result = await response.json();
        return new Response(JSON.stringify({ success: true, data: result }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    if (request.method === "GET") {
      return new Response("Endpoint non riconosciuto", { status: 404, headers: corsHeaders });
    }
    return new Response("Metodo non consentito", { status: 405 });
  }
};