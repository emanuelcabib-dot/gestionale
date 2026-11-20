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

function errorResponse(message, corsHeaders, status = 400) {
  return jsonResponse({ success: false, error: message }, corsHeaders, status);
}

function upstreamErrorStatus(response) {
  return response.status === 429 ? 429 : response.status === 403 ? 403 : 500;
}

function isRecordId(value) {
  return (typeof value === "number" || (typeof value === "string" && /^\d+$/.test(value))) &&
    Number.isSafeInteger(Number(value)) && Number(value) > 0;
}

function parseFiniteNumber(value) {
  if ((typeof value !== "number" && typeof value !== "string") ||
      (typeof value === "string" && !value.trim())) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function parseCalendarDate(value) {
  if (typeof value !== "string") return null;
  const match = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(value);
  if (!match) return null;
  const [, dayText, monthText, yearText] = match;
  const day = Number(dayText);
  const month = Number(monthText);
  const year = Number(yearText);
  if (year < 1900 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31) return null;
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
  return { day, month, year, epochStart: Math.floor(date.getTime() / 1000) };
}

function recordMatchesDate(record, date) {
  const timestamp = Number(record?.fields?.Data);
  if (!Number.isFinite(timestamp)) return false;
  const recordDate = new Date(timestamp * 1000);
  return recordDate.getUTCFullYear() === date.year &&
    recordDate.getUTCMonth() + 1 === date.month &&
    recordDate.getUTCDate() === date.day;
}

async function getGristRecords(base, table, headers) {
  const response = await fetch(`${base}/${table}/records`, { headers });
  if (!response.ok) throw new Error("Impossibile verificare i dati su Grist");
  const data = await response.json();
  return Array.isArray(data.records) ? data.records : [];
}

function validString(value, maxLength, allowEmpty = true) {
  return typeof value === "string" &&
    value.length <= maxLength &&
    (allowEmpty || Boolean(value.trim()));
}

function validInteger(value, minimum, maximum) {
  const number = parseFiniteNumber(value);
  return number !== null && Number.isInteger(number) && number >= minimum && number <= maximum;
}

function numeroGiorniDelMese(mese) {
  if (mese === 2) return 29;
  return [4, 6, 9, 11].includes(mese) ? 30 : 31;
}

async function validateCalendarWrite(base, headers, date, kind, body, recordId) {
  const [holidays, absences, absenceTypes, entries, types] = await Promise.all([
    getGristRecords(base, "Festivita", headers),
    getGristRecords(base, "Registro_Ferie_Permessi", headers),
    getGristRecords(base, "Tipi_Assenza", headers),
    getGristRecords(base, "Prova", headers),
    getGristRecords(base, kind === "presenze" ? "Tipi_Timbratura" : "Tipi_Assenza", headers)
  ]);
  const holiday = holidays.some(record => {
    const fields = record.fields || {};
    return fields.Attivo === true &&
      Number(fields.Giorno) === date.day &&
      Number(fields.Mese) === date.month &&
      (fields.Ricorrente === true || date.year === new Date().getFullYear());
  });
  if (holiday) return { status: 403, error: "Non è possibile registrare dati in una festività attiva." };

  if (kind === "presenze") {
    const tipo = types.find(record => record.fields?.Nome === body.evento && record.fields?.Attivo === true);
    if (!tipo) return { status: 400, error: "Tipo di timbratura non valido." };
    const bloccoAssenza = absences.some(record => {
      if (!recordMatchesDate(record, date)) return false;
      const absenceName = String(record.fields?.Tipo_Assenza || "").trim().toLowerCase();
      return absenceTypes.some(absenceType =>
        absenceType.fields?.Attivo === true &&
        absenceType.fields?.Blocca_Timbrature === true &&
        String(absenceType.fields?.Nome || "").trim().toLowerCase() === absenceName
      );
    });
    if (bloccoAssenza && recordId === null) {
      return { status: 403, error: "La data è bloccata da un'assenza." };
    }

    const entriesToday = entries.filter(record =>
      recordMatchesDate(record, date) && Number(record.id) !== recordId
    );
    if (recordId === null && entriesToday.some(record => record.fields?.Evento === "Uscita")) {
      return { status: 403, error: "La giornata ha già una timbratura di uscita." };
    }
    if (tipo.fields?.Unico_Al_Giorno === true &&
        entriesToday.some(record => record.fields?.Evento === body.evento)) {
      return { status: 403, error: "Il tipo di timbratura è già registrato per questa data." };
    }
    return null;
  }

  const tipo = types.find(record => record.fields?.Nome === body.tipoAssenza && record.fields?.Attivo === true);
  if (!tipo) return { status: 400, error: "Tipo di assenza non valido." };
  if (absences.some(record =>
    recordMatchesDate(record, date) && Number(record.id) !== recordId
  )) {
    return { status: 403, error: "È già presente un'assenza in questa data." };
  }
  if (entries.some(record => recordMatchesDate(record, date))) {
    return { status: 403, error: "La data contiene già una timbratura." };
  }
  return null;
}

const SESSION_TTL_SECONDS = 24 * 60 * 60;
const TWOFA_SETUP_TTL_SECONDS = 10 * 60;
const TWOFA_CHALLENGE_TTL_SECONDS = 5 * 60;
const TRUSTED_DEVICE_TTL_SECONDS = 30 * 24 * 60 * 60;
const TWOFA_RATE_LIMIT_WINDOW_SECONDS = 15 * 60;
const TWOFA_RATE_LIMIT_MAX_ATTEMPTS = 5;
const TWOFA_SETUP_START_MAX_ATTEMPTS = 10;
const TWOFA_TOTP_STEP_SECONDS = 30;
const TWOFA_TOTP_TOLERANCE_STEPS = 1;
const TWOFA_BACKUP_CODE_COUNT = 10;
const TWOFA_ISSUER = "Gestionale";
const TWOFA_BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

async function getSession(env, token) {
  if (typeof token !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token)) {
    return null;
  }
  const key = `session:${token}`;
  const value = await env.AUTH_KV.get(key);
  if (!value) return null;
  let session;
  try {
    session = JSON.parse(value);
  } catch {
    await env.AUTH_KV.delete(key);
    return null;
  }
  if (!session || typeof session !== "object" || Array.isArray(session) ||
      typeof session.username !== "string" ||
      !Number.isInteger(session.expiresAt) ||
      session.expiresAt <= Math.floor(Date.now() / 1000)) {
    await env.AUTH_KV.delete(key);
    return null;
  }
  return { key, session };
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

function twofaUsernameKey(username) {
  return encodeCredentialId(username);
}

function twofaDevicePrefix(username) {
  return `trusted_device:${twofaUsernameKey(username)}:`;
}

async function twofaListDevices(env, username) {
  const keys = [];
  let cursor;
  const prefix = twofaDevicePrefix(username);
  do {
    const page = await env.AUTH_KV.list({ prefix, cursor, limit: 1000 });
    keys.push(...page.keys);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return keys;
}

function twofaClientAddress(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function twofaRateKey(scope) {
  return `twofa_rate:${base64UrlEncode(textEncoder.encode(scope))}`;
}

async function twofaConsumeOperation(env, scope) {
  const key = `twofa_ops:${base64UrlEncode(textEncoder.encode(scope))}`;
  const value = await env.AUTH_KV.get(key);
  let count = 0;
  if (value) {
    try {
      count = Number(JSON.parse(value).count) || 0;
    } catch {
      count = 0;
    }
  }
  if (count >= TWOFA_RATE_LIMIT_MAX_ATTEMPTS) return true;
  await env.AUTH_KV.put(key, JSON.stringify({ count: count + 1 }), {
    expirationTtl: TWOFA_RATE_LIMIT_WINDOW_SECONDS
  });
  return false;
}

async function twofaConsumeSetupStart(env, scope) {
  const key = `twofa_setup_ops:${base64UrlEncode(textEncoder.encode(scope))}`;
  const value = await env.AUTH_KV.get(key);
  let count = 0;
  if (value) {
    try {
      count = Number(JSON.parse(value).count) || 0;
    } catch {
      count = 0;
    }
  }
  if (count >= TWOFA_SETUP_START_MAX_ATTEMPTS) return true;
  await env.AUTH_KV.put(key, JSON.stringify({ count: count + 1 }), {
    expirationTtl: TWOFA_RATE_LIMIT_WINDOW_SECONDS
  });
  return false;
}

async function twofaIsRateLimited(env, scope) {
  const record = await env.AUTH_KV.get(twofaRateKey(scope));
  if (!record) return false;
  try {
    return JSON.parse(record).count >= TWOFA_RATE_LIMIT_MAX_ATTEMPTS;
  } catch {
    return false;
  }
}

async function twofaRecordFailure(env, scope) {
  const key = twofaRateKey(scope);
  const value = await env.AUTH_KV.get(key);
  let count = 0;
  if (value) {
    try {
      count = Number(JSON.parse(value).count) || 0;
    } catch {
      count = 0;
    }
  }
  await env.AUTH_KV.put(key, JSON.stringify({ count: count + 1 }), {
    expirationTtl: TWOFA_RATE_LIMIT_WINDOW_SECONDS
  });
}

async function twofaClearFailures(env, scope) {
  await env.AUTH_KV.delete(twofaRateKey(scope));
}

function twofaRateLimitResponse(corsHeaders) {
  return privateJsonResponse({ success: false, error: "Troppi tentativi. Riprova tra qualche minuto." }, corsHeaders, 429);
}

async function twofaSha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function twofaBase32Encode(bytes) {
  let buffer = 0;
  let bits = 0;
  let result = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) result += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(buffer << (5 - bits)) & 31];
  return result;
}

function twofaBase32Decode(value) {
  if (typeof value !== "string" || !/^[A-Z2-7]+$/.test(value)) {
    throw new Error("Segreto TOTP non valido");
  }
  let buffer = 0;
  let bits = 0;
  const result = [];
  for (const character of value) {
    buffer = (buffer << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(character);
    bits += 5;
    if (bits >= 8) {
      result.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(result);
}

async function twofaTotpAtStep(secret, timeStep) {
  const key = await crypto.subtle.importKey(
    "raw",
    twofaBase32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(timeStep), false);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 1000000).padStart(6, "0");
}

async function twofaVerifyTotp(secret, code, lastTimeStep = -1) {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) return null;
  const currentStep = Math.floor(Date.now() / 1000 / TWOFA_TOTP_STEP_SECONDS);
  for (let offset = -TWOFA_TOTP_TOLERANCE_STEPS; offset <= TWOFA_TOTP_TOLERANCE_STEPS; offset++) {
    const step = currentStep + offset;
    if (step > lastTimeStep && equalSecret(await twofaTotpAtStep(secret, step), code)) return step;
  }
  return null;
}

async function twofaGenerateBackupCodes(env, username) {
  const codes = [];
  const records = [];
  for (let index = 0; index < TWOFA_BACKUP_CODE_COUNT; index++) {
    const random = new Uint8Array(16);
    crypto.getRandomValues(random);
    let raw = "";
    for (const byte of random) raw += TWOFA_BACKUP_ALPHABET[byte % TWOFA_BACKUP_ALPHABET.length];
    const code = `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const normalized = code.replace(/-/g, "");
    const hashInput = new Uint8Array(salt.length + textEncoder.encode(normalized).length);
    hashInput.set(salt);
    hashInput.set(textEncoder.encode(normalized), salt.length);
    records.push({
      salt: base64UrlEncode(salt),
      hash: base64UrlEncode(await twofaSha256(hashInput))
    });
    codes.push(code);
  }
  await env.AUTH_KV.put(`twofa_backup:${twofaUsernameKey(username)}`, JSON.stringify(records));
  return codes;
}

async function twofaConsumeBackupCode(env, username, code) {
  if (typeof code !== "string" || !/^[A-Za-z2-9-]{12,24}$/.test(code)) return false;
  const key = `twofa_backup:${twofaUsernameKey(username)}`;
  const value = await env.AUTH_KV.get(key);
  if (!value) return false;
  let records;
  try {
    records = JSON.parse(value);
  } catch {
    await env.AUTH_KV.delete(key);
    return false;
  }
  const normalized = code.replace(/-/g, "").toUpperCase();
  const normalizedBytes = textEncoder.encode(normalized);
  let matched = -1;
  for (let index = 0; index < records.length; index++) {
    const salt = base64UrlDecode(records[index].salt);
    const bytes = new Uint8Array(salt.length + normalizedBytes.length);
    bytes.set(salt);
    bytes.set(normalizedBytes, salt.length);
    const hash = base64UrlEncode(await twofaSha256(bytes));
    if (equalSecret(hash, records[index].hash)) matched = index;
  }
  if (matched < 0) return false;
  records.splice(matched, 1);
  if (records.length) await env.AUTH_KV.put(key, JSON.stringify(records));
  else await env.AUTH_KV.delete(key);
  return true;
}

async function twofaVerifyProof(env, username, code) {
  const key = `twofa:${twofaUsernameKey(username)}`;
  const value = await env.AUTH_KV.get(key);
  if (!value) return false;
  const record = JSON.parse(value);
  const step = await twofaVerifyTotp(record.secret, code, record.lastTimeStep ?? -1);
  if (step !== null) {
    record.lastTimeStep = step;
    await env.AUTH_KV.put(key, JSON.stringify(record));
    return true;
  }
  return twofaConsumeBackupCode(env, username, code);
}

function twofaDeviceLabel(request) {
  const userAgent = request.headers.get("User-Agent") || "";
  if (/iphone|ipad/i.test(userAgent)) return "Dispositivo Apple";
  if (/android/i.test(userAgent)) return "Dispositivo Android";
  if (/windows/i.test(userAgent)) return "Dispositivo Windows";
  if (/macintosh|mac os/i.test(userAgent)) return "Dispositivo Mac";
  if (/linux/i.test(userAgent)) return "Dispositivo Linux";
  return "Browser";
}

async function twofaCheckTrustedDevice(env, username, deviceId, token) {
  if (typeof deviceId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(deviceId) ||
      typeof token !== "string" || !/^[A-Za-z0-9_-]{40,50}$/.test(token)) return false;
  const key = `${twofaDevicePrefix(username)}${deviceId}`;
  const value = await env.AUTH_KV.get(key);
  if (!value) return false;
  let record;
  try {
    record = JSON.parse(value);
  } catch {
    await env.AUTH_KV.delete(key);
    return false;
  }
  if (!Number.isInteger(record.expiresAt) || record.expiresAt <= Math.floor(Date.now() / 1000)) {
    await env.AUTH_KV.delete(key);
    return false;
  }
  const hash = base64UrlEncode(await twofaSha256(textEncoder.encode(token)));
  if (!equalSecret(hash, record.tokenHash)) return false;
  record.lastUsedAt = Math.floor(Date.now() / 1000);
  const remaining = Math.max(1, record.expiresAt - record.lastUsedAt);
  await env.AUTH_KV.put(key, JSON.stringify(record), { expirationTtl: remaining });
  return true;
}

async function twofaStartLogin(env, corsHeaders, username, body) {
  const enabled = await env.AUTH_KV.get(`twofa:${twofaUsernameKey(username)}`);
  if (!enabled) return await issueSession(env, corsHeaders, username);
  if (await twofaCheckTrustedDevice(env, username, body.deviceId, body.trustedDeviceToken)) {
    return await issueSession(env, corsHeaders, username);
  }
  const challengeId = crypto.randomUUID();
  await env.AUTH_KV.put(`twofa_pending:${challengeId}`, JSON.stringify({
    username,
    attempts: 0,
    deviceId: typeof body.deviceId === "string" ? body.deviceId : ""
  }), { expirationTtl: TWOFA_CHALLENGE_TTL_SECONDS });
  return privateJsonResponse({ success: true, requires2FA: true, challengeId }, corsHeaders);
}

async function issueSession(env, corsHeaders, username, extra = {}) {
  const sessionToken = crypto.randomUUID();
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  await env.AUTH_KV.put(`session:${sessionToken}`, JSON.stringify({ username, expiresAt }), {
    expirationTtl: SESSION_TTL_SECONDS
  });
  return privateJsonResponse({
    success: true,
    token: sessionToken,
    urls: { dashboard: env.URL_DASHBOARD, impostazioni: env.URL_IMPOSTAZIONI },
    ...extra
  }, corsHeaders);
}

const GRIST_API_BASE = "https://gestionale-lavoro-emanuel-01.getgrist.com/api";
export default {
  async fetch(request, env, ctx) {
    const defaultOrigins = ["https://emanuelcabib-dot.github.io"];
    const configuredOrigins = typeof env.ALLOWED_ORIGINS === "string"
      ? env.ALLOWED_ORIGINS.split(",").map(origin => origin.trim()).filter(Boolean)
      : [];
    const allowedOrigins = new Set(configuredOrigins.length ? configuredOrigins : defaultOrigins);
    const requestOrigin = request.headers.get("Origin");
    const corsHeaders = {
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin",
    };
    const originAllowed = requestOrigin !== null && allowedOrigins.has(requestOrigin);
    if (originAllowed) corsHeaders["Access-Control-Allow-Origin"] = requestOrigin;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: originAllowed ? 204 : 403, headers: corsHeaders });
    }

    const url = new URL(request.url);
    if (request.method === "POST") {
      try {
        let body;
        try {
          body = await request.json();
        } catch (e) {
          return errorResponse("JSON non valido nel body", corsHeaders, 400);
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) {
          return errorResponse("JSON non valido nel body", corsHeaders, 400);
        }

        if (body.tipo === "get_readme_doc" && !originAllowed) {
          return errorResponse("Origine non autorizzata", corsHeaders, 403);
        }

        if (body.tipo === "auth") {
          if (!env.COMPANY_USERNAME || !env.COMPANY_PASSWORD || !env.GRIST_API_KEY || !env.AUTH_KV) {
            return jsonResponse({ success: false, error: "Configurazione credenziali incompleta sul Worker" }, corsHeaders, 500);
          }
          const username = typeof body.username === "string" ? body.username.trim() : "";
          const rateScope = `login:${twofaClientAddress(request)}`;
          if (await twofaIsRateLimited(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          const validUsername = equalSecret(username, env.COMPANY_USERNAME.trim());
          const validPassword = equalSecret(body.password, env.COMPANY_PASSWORD);
          if (!username || !validUsername || !validPassword) {
            await twofaRecordFailure(env, rateScope);
            return jsonResponse({ success: false, error: "Nome utente o password non validi" }, corsHeaders, 401);
          }
          await twofaClearFailures(env, rateScope);
          await syncPasswordVersion(env, username);
          return await twofaStartLogin(env, corsHeaders, username, body);
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
          const rateScope = `login:${twofaClientAddress(request)}`;
          if (await twofaIsRateLimited(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          if (!username || !equalSecret(username, env.COMPANY_USERNAME.trim())) {
            await twofaRecordFailure(env, rateScope);
            return jsonResponse({ success: false, error: "Nome utente non valido" }, corsHeaders, 401);
          }
          const authFailure = async message => {
            await twofaRecordFailure(env, rateScope);
            return jsonResponse({ success: false, error: message }, corsHeaders, 401);
          };
          await syncPasswordVersion(env, username);
          const response = body.credential?.response;
          let clientDataJSON;
          let clientData;
          try {
            clientDataJSON = base64UrlDecode(response?.clientDataJSON);
            clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
          } catch (error) {
            return await authFailure("Dati client WebAuthn non validi");
          }
          const challengeRecord = await consumeWebAuthnChallenge(env, clientData.challenge, username, "assertion");
          if (!challengeRecord) {
            return await authFailure("Sfida WebAuthn scaduta o non valida");
          }
          const context = { origin: challengeRecord.origin, rpId: challengeRecord.rpId };
          let credentialId;
          try {
            await verifyClientData(clientDataJSON, "webauthn.get", clientData.challenge, context);
            credentialId = base64UrlEncode(base64UrlDecode(body.credential?.rawId));
            if (body.credential?.type !== "public-key" || credentialId !== body.credential?.id) {
              return await authFailure("Credenziale WebAuthn non valida");
            }
          } catch (error) {
            return await authFailure("Risposta WebAuthn non valida");
          }
          const credentialKey = `credential:${encodeCredentialId(username)}:${credentialId}`;
          const storedCredential = await env.AUTH_KV.get(credentialKey);
          if (!storedCredential) {
            return await authFailure("Credenziale WebAuthn non riconosciuta");
          }
          const credential = JSON.parse(storedCredential);
          let parsedData;
          try {
            const authenticatorData = base64UrlDecode(response.authenticatorData);
            const signature = base64UrlDecode(response.signature);
            parsedData = parseAuthenticatorData(authenticatorData);
            if (!await assertRpIdHash(authenticatorData, context.rpId) ||
                !await verifyAssertionSignature(credential, authenticatorData, clientDataJSON, signature)) {
              return await authFailure("Verifica biometrica non riuscita");
            }
          } catch (error) {
            return await authFailure("Firma WebAuthn non valida");
          }
          if (credential.signCount > 0 && parsedData.signCount <= credential.signCount) {
            return await authFailure("Contatore WebAuthn non valido");
          }
          credential.signCount = parsedData.signCount;
          await env.AUTH_KV.put(credentialKey, JSON.stringify(credential));
          await twofaClearFailures(env, rateScope);
          return await twofaStartLogin(env, corsHeaders, username, body);
        }

        if (body.tipo === "verify_2fa") {
          const challengeId = body.challengeId;
          if (typeof challengeId !== "string" ||
              !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(challengeId)) {
            return errorResponse("Sfida 2FA non valida o scaduta.", corsHeaders, 401);
          }
          const challengeKey = `twofa_pending:${challengeId}`;
          const challengeValue = await env.AUTH_KV.get(challengeKey);
          if (!challengeValue) return errorResponse("Sfida 2FA non valida o scaduta.", corsHeaders, 401);
          const challenge = JSON.parse(challengeValue);
          const rateScope = `verify_2fa:${twofaClientAddress(request)}:${challenge.username}`;
          const challengeRateScope = `verify_2fa_challenge:${challengeId}`;
          if (await twofaIsRateLimited(env, rateScope) || await twofaIsRateLimited(env, challengeRateScope)) {
            return twofaRateLimitResponse(corsHeaders);
          }
          const validProof = await twofaVerifyProof(env, challenge.username, body.code);
          if (!validProof) {
            challenge.attempts = (Number(challenge.attempts) || 0) + 1;
            if (challenge.attempts >= TWOFA_RATE_LIMIT_MAX_ATTEMPTS) {
              await env.AUTH_KV.delete(challengeKey);
            } else {
              await env.AUTH_KV.put(challengeKey, JSON.stringify(challenge), {
                expirationTtl: TWOFA_CHALLENGE_TTL_SECONDS
              });
            }
            await twofaRecordFailure(env, rateScope);
            await twofaRecordFailure(env, challengeRateScope);
            return errorResponse("Codice 2FA non valido o già utilizzato.", corsHeaders, 401);
          }
          await env.AUTH_KV.delete(challengeKey);
          await twofaClearFailures(env, rateScope);
          await twofaClearFailures(env, challengeRateScope);
          const extra = {};
          if (body.rememberDevice === true) {
            const deviceId = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(challenge.deviceId)
              ? challenge.deviceId
              : crypto.randomUUID();
            const trustedDeviceTokenBytes = new Uint8Array(32);
            crypto.getRandomValues(trustedDeviceTokenBytes);
            const trustedDeviceToken = base64UrlEncode(trustedDeviceTokenBytes);
            const createdAt = Math.floor(Date.now() / 1000);
            const expiresAt = createdAt + TRUSTED_DEVICE_TTL_SECONDS;
            await env.AUTH_KV.put(`${twofaDevicePrefix(challenge.username)}${deviceId}`, JSON.stringify({
              tokenHash: base64UrlEncode(await twofaSha256(textEncoder.encode(trustedDeviceToken))),
              deviceId,
              label: twofaDeviceLabel(request),
              createdAt,
              lastUsedAt: createdAt,
              expiresAt
            }), { expirationTtl: TRUSTED_DEVICE_TTL_SECONDS });
            extra.trustedDeviceToken = trustedDeviceToken;
            extra.deviceId = deviceId;
          }
          return await issueSession(env, corsHeaders, challenge.username, extra);
        }

        const session = await getSession(env, body.token);
        if (!session) {
          if (body.tipo === "logout" && typeof body.token === "string" &&
              /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.token)) {
            await env.AUTH_KV.delete(`session:${body.token}`);
          }
          return errorResponse("Sessione non autorizzata o scaduta", corsHeaders, 403);
        }
        if (body.tipo === "logout") {
          await env.AUTH_KV.delete(session.key);
          return privateJsonResponse({ success: true }, corsHeaders);
        }

        if (body.tipo === "get_readme_doc") {
          return privateJsonResponse({ success: true, markdown: env.README_DOC ?? "" }, corsHeaders);
        }

        if (body.tipo === "twofa_setup_start") {
          const rateScope = `sensitive:${twofaClientAddress(request)}:${session.session.username}`;
          if (await twofaConsumeSetupStart(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          if (await env.AUTH_KV.get(`twofa:${twofaUsernameKey(session.session.username)}`)) {
            return errorResponse("La verifica in due fattori è già attiva.", corsHeaders, 409);
          }
          const secretBytes = new Uint8Array(20);
          crypto.getRandomValues(secretBytes);
          const secret = twofaBase32Encode(secretBytes);
          await env.AUTH_KV.put(`twofa_setup:${twofaUsernameKey(session.session.username)}`, JSON.stringify({
            secret,
            createdAt: Math.floor(Date.now() / 1000)
          }), { expirationTtl: TWOFA_SETUP_TTL_SECONDS });
          const label = `${TWOFA_ISSUER}:${session.session.username}`;
          const uri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(TWOFA_ISSUER)}&algorithm=SHA1&digits=6&period=${TWOFA_TOTP_STEP_SECONDS}`;
          return privateJsonResponse({ success: true, secret, uri }, corsHeaders);
        }

        if (body.tipo === "twofa_setup_confirm") {
          const username = session.session.username;
          const rateScope = `sensitive:${twofaClientAddress(request)}:${username}`;
          if (await twofaIsRateLimited(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          if (await twofaConsumeOperation(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          const setupKey = `twofa_setup:${twofaUsernameKey(username)}`;
          const setupValue = await env.AUTH_KV.get(setupKey);
          if (!setupValue) return errorResponse("La configurazione 2FA è scaduta. Avviala di nuovo.", corsHeaders, 400);
          const setup = JSON.parse(setupValue);
          const step = await twofaVerifyTotp(setup.secret, body.code);
          if (step === null) {
            await twofaRecordFailure(env, rateScope);
            return errorResponse("Codice Authenticator non valido.", corsHeaders, 401);
          }
          await env.AUTH_KV.put(`twofa:${twofaUsernameKey(username)}`, JSON.stringify({
            secret: setup.secret,
            lastTimeStep: step
          }));
          await env.AUTH_KV.delete(setupKey);
          const backupCodes = await twofaGenerateBackupCodes(env, username);
          await twofaClearFailures(env, rateScope);
          return privateJsonResponse({ success: true, backupCodes, remainingBackupCodes: backupCodes.length }, corsHeaders);
        }

        if (body.tipo === "twofa_status" || body.tipo === "twofa_devices") {
          const username = session.session.username;
          const enabled = Boolean(await env.AUTH_KV.get(`twofa:${twofaUsernameKey(username)}`));
          const backupValue = await env.AUTH_KV.get(`twofa_backup:${twofaUsernameKey(username)}`);
          let remainingBackupCodes = 0;
          if (backupValue) {
            try {
              const records = JSON.parse(backupValue);
              remainingBackupCodes = Array.isArray(records) ? records.length : 0;
            } catch {
              await env.AUTH_KV.delete(`twofa_backup:${twofaUsernameKey(username)}`);
            }
          }
          const devices = [];
          for (const key of await twofaListDevices(env, username)) {
            const value = await env.AUTH_KV.get(key.name);
            if (!value) continue;
            try {
              const record = JSON.parse(value);
              if (!Number.isInteger(record.expiresAt) || record.expiresAt <= Math.floor(Date.now() / 1000)) {
                await env.AUTH_KV.delete(key.name);
                continue;
              }
              devices.push({
                deviceId: record.deviceId,
                label: record.label,
                createdAt: record.createdAt,
                lastUsedAt: record.lastUsedAt,
                expiresAt: record.expiresAt,
                current: record.deviceId === body.deviceId
              });
            } catch {
              await env.AUTH_KV.delete(key.name);
            }
          }
          return privateJsonResponse({ success: true, enabled, remainingBackupCodes, devices }, corsHeaders);
        }

        if (body.tipo === "twofa_backup_regenerate" || body.tipo === "twofa_disable") {
          const username = session.session.username;
          const rateScope = `sensitive:${twofaClientAddress(request)}:${username}`;
          if (await twofaIsRateLimited(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          if (await twofaConsumeOperation(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          const validProof = await twofaVerifyProof(env, username, body.code);
          if (!validProof) {
            await twofaRecordFailure(env, rateScope);
            return errorResponse("Codice Authenticator o codice di backup non valido.", corsHeaders, 401);
          }
          await twofaClearFailures(env, rateScope);
          if (body.tipo === "twofa_backup_regenerate") {
            const backupCodes = await twofaGenerateBackupCodes(env, username);
            return privateJsonResponse({ success: true, backupCodes, remainingBackupCodes: backupCodes.length }, corsHeaders);
          }
          await env.AUTH_KV.delete(`twofa:${twofaUsernameKey(username)}`);
          await env.AUTH_KV.delete(`twofa_backup:${twofaUsernameKey(username)}`);
          await env.AUTH_KV.delete(`twofa_setup:${twofaUsernameKey(username)}`);
          for (const key of await twofaListDevices(env, username)) await env.AUTH_KV.delete(key.name);
          return privateJsonResponse({ success: true }, corsHeaders);
        }

        if (body.tipo === "twofa_device_revoke" || body.tipo === "twofa_devices_revoke") {
          const username = session.session.username;
          const rateScope = `sensitive:${twofaClientAddress(request)}:${username}`;
          if (await twofaIsRateLimited(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          if (await twofaConsumeOperation(env, rateScope)) return twofaRateLimitResponse(corsHeaders);
          const devices = await twofaListDevices(env, username);
          if (body.tipo === "twofa_device_revoke") {
            if (typeof body.deviceId !== "string" ||
                !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.deviceId)) {
              await twofaRecordFailure(env, rateScope);
              return errorResponse("Identificativo dispositivo non valido.", corsHeaders, 400);
            }
            await env.AUTH_KV.delete(`${twofaDevicePrefix(username)}${body.deviceId}`);
            await twofaClearFailures(env, rateScope);
            return privateJsonResponse({ success: true, currentRevoked: body.deviceId === body.currentDeviceId }, corsHeaders);
          }
          for (const key of devices) await env.AUTH_KV.delete(key.name);
          await twofaClearFailures(env, rateScope);
          return privateJsonResponse({
            success: true,
            currentRevoked: devices.some(key => key.name.endsWith(`:${body.currentDeviceId}`))
          }, corsHeaders);
        }

        if (body.tipo === "get_drive_pdf_url") {
          if (!env.DRIVE_PDF_URL) {
            return privateJsonResponse({ success: false, error: "Indirizzo Google Drive non configurato sul Worker" }, corsHeaders, 503);
          }
          let driveUrl;
          try {
            driveUrl = new URL(env.DRIVE_PDF_URL);
          } catch {
            return privateJsonResponse({ success: false, error: "Indirizzo Google Drive non valido sul Worker" }, corsHeaders, 500);
          }
          if (driveUrl.protocol !== "https:" ||
              !["drive.google.com", "docs.google.com"].includes(driveUrl.hostname) ||
              driveUrl.username || driveUrl.password) {
            return privateJsonResponse({ success: false, error: "Indirizzo Google Drive non valido sul Worker" }, corsHeaders, 500);
          }
          return privateJsonResponse({ success: true, url: driveUrl.href }, corsHeaders);
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
            return errorResponse("Registrazione WebAuthn non valida", corsHeaders, 400);
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
        const BASE_GRIST = `${env.GRIST_API_BASE || GRIST_API_BASE}/docs/${DOC_ID}/tables`;
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
          if (!isRecordId(body.id_riga) ||
              !validString(body.valore, 2000) ||
              !validString(body.descrizione, 5000)) {
            return errorResponse("Dati Config_App non validi", corsHeaders, 400);
          }
          const idRecord = Number(body.id_riga);
          const configRecords = await getGristRecords(BASE_GRIST, "Config_App", headersGrist);
          const configRecord = configRecords.find(record => Number(record.id) === idRecord);
          if (!configRecord) return errorResponse("Parametro Config_App non trovato", corsHeaders, 400);
          const configLimits = {
            "Anno inizio storico": [1900, new Date().getFullYear()],
            "Giorni anticipo assenze": [0, 3650],
            "Giorni anticipo scadenze": [0, 3650],
            "Giorno avviso fine mese": [1, 31],
            "Ora minima ingresso": [0, 23],
            "Ora minima uscita": [0, 23]
          };
          const parametro = configRecord.fields?.Parametro;
          const configLimit = Object.hasOwn(configLimits, parametro) ? configLimits[parametro] : null;
          if (configLimit) {
            const configValue = parseFiniteNumber(body.valore);
            if (!validInteger(configValue, configLimit[0], configLimit[1])) {
              return errorResponse("Valore Config_App fuori intervallo", corsHeaders, 400);
            }
          }
          const resMod = await fetch(`${BASE_GRIST}/Config_App/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Valore": body.valore, "Descrizione": body.descrizione } }] })
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
          const anno = parseFiniteNumber(body.anno_inizio);
          const ferie = parseFiniteNumber(body.ferie_annuo);
          const permessi = parseFiniteNumber(body.permessi_annuo);
          if (!isRecordId(body.id_riga) || !validInteger(anno, 1900, 9999) ||
              ferie === null || ferie < 0 || ferie > 366 ||
              permessi === null || permessi < 0 || permessi > 8760) {
            return errorResponse("Parametri contrattuali non validi", corsHeaders, 400);
          }
          const idRecord = Number(body.id_riga);
          const resMod = await fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Anno_Inizio_Validita": anno, "Ferie_Annuo_Spettante": ferie, "Permessi_Annuo_Spettante": permessi } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Parametri_contrattuali" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_contrattuali") {
          const anno = parseFiniteNumber(body.anno_inizio);
          const ferie = parseFiniteNumber(body.ferie_annuo);
          const permessi = parseFiniteNumber(body.permessi_annuo);
          if (!validInteger(anno, 1900, 9999) ||
              ferie === null || ferie < 0 || ferie > 366 ||
              permessi === null || permessi < 0 || permessi > 8760) {
            return errorResponse("Parametri contrattuali non validi", corsHeaders, 400);
          }
          const resAdd = await fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Anno_Inizio_Validita": anno, "Ferie_Annuo_Spettante": ferie, "Permessi_Annuo_Spettante": permessi } }] })
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
          if (!isRecordId(body.id_riga) || !validString(body.nome, 100, false) ||
              typeof body.blocca !== "boolean" || typeof body.attivo !== "boolean") {
            return errorResponse("Tipo di assenza non valido", corsHeaders, 400);
          }
          const idRecord = Number(body.id_riga);
          const resMod = await fetch(`${BASE_GRIST}/Tipi_Assenza/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Nome": body.nome.trim(), "Blocca_Timbrature": body.blocca, "Attivo": body.attivo } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Tipi_Assenza" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_tipo_assenza") {
          if (!validString(body.nome, 100, false) ||
              typeof body.blocca !== "boolean" || typeof body.attivo !== "boolean") {
            return errorResponse("Nome o regole del tipo di assenza non validi", corsHeaders, 400);
          }
          const nome = body.nome.trim();
          const resAdd = await fetch(`${BASE_GRIST}/Tipi_Assenza/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Nome": nome, "Blocca_Timbrature": body.blocca, "Attivo": body.attivo } }] })
          });
          if (!resAdd.ok) return errorResponse("Errore aggiunta Tipi_Assenza", corsHeaders, upstreamErrorStatus(resAdd));
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_tipi_timbratura") {
          const res = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Tipi_Timbratura" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_tipo_timbratura") {
          const ordine = parseFiniteNumber(body.ordine);
          if (!isRecordId(body.id_riga) || !validString(body.nome, 100, false) ||
              typeof body.unico !== "boolean" || typeof body.attivo !== "boolean" ||
              !validInteger(ordine, 0, 9999)) {
            return errorResponse("Tipo di timbratura non valido", corsHeaders, 400);
          }
          const idRecord = Number(body.id_riga);
          const resMod = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Nome": body.nome.trim(), "Unico_Al_Giorno": body.unico, "Attivo": body.attivo, "Ordine": ordine } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Tipi_Timbratura" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_tipo_timbratura") {
          const ordine = parseFiniteNumber(body.ordine);
          if (!validString(body.nome, 100, false) || !validInteger(ordine, 0, 9999) ||
              typeof body.unico !== "boolean" || typeof body.attivo !== "boolean") {
            return errorResponse("Nome, ordine o regole del tipo di timbratura non validi", corsHeaders, 400);
          }
          const nome = body.nome.trim();
          const resAdd = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Nome": nome, "Unico_Al_Giorno": body.unico, "Attivo": body.attivo, "Ordine": ordine } }] })
          });
          if (!resAdd.ok) return errorResponse("Errore aggiunta Tipi_Timbratura", corsHeaders, upstreamErrorStatus(resAdd));
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_festivita") {
          const res = await fetch(`${BASE_GRIST}/Festivita/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Festivita" }), { status: res.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_festivita" || body.tipo === "modifica_festivita") {
          const descrizione = typeof body.descrizione === "string" ? body.descrizione.trim() : "";
          const giorno = parseFiniteNumber(body.giorno);
          const mese = parseFiniteNumber(body.mese);
          const modifica = body.tipo === "modifica_festivita";
          if (!validString(descrizione, 200, false) ||
              !validInteger(giorno, 1, 31) || !validInteger(mese, 1, 12) ||
              giorno > numeroGiorniDelMese(mese) ||
              typeof body.ricorrente !== "boolean" || typeof body.attivo !== "boolean" ||
              (modifica && !isRecordId(body.id_riga))) {
            return errorResponse("Descrizione, giorno o mese della festività non validi", corsHeaders, 400);
          }
          const festivitaEsistenti = await getGristRecords(BASE_GRIST, "Festivita", headersGrist);
          if (festivitaEsistenti.some(record =>
            Number(record.id) !== Number(body.id_riga) &&
            Number(record.fields?.Giorno) === giorno &&
            Number(record.fields?.Mese) === mese
          )) {
            return errorResponse("Esiste già una festività per questa data", corsHeaders, 400);
          }

          const fields = { "Descrizione": descrizione, "Giorno": giorno, "Mese": mese, "Ricorrente": body.ricorrente, "Attivo": body.attivo };
          const response = await fetch(`${BASE_GRIST}/Festivita/records`, {
            method: modifica ? "PATCH" : "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [modifica ? { id: Number(body.id_riga), fields } : { fields }] })
          });
          if (!response.ok) return errorResponse(modifica ? "Errore modifica Festivita" : "Errore aggiunta Festivita", corsHeaders, upstreamErrorStatus(response));
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_avvisi") {
          const res = await fetch(`${BASE_GRIST}/Avvisi/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Avvisi" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_avviso") {
          const dataScadenza = body.data_scadenza === null ? 0 : parseFiniteNumber(body.data_scadenza);
          if (!isRecordId(body.id_riga) ||
              !validString(body.titolo, 200, false) ||
              !validString(body.messaggio, 10000, false) ||
              !["Info", "Urgente", "Scadenza"].includes(body.tipo_avviso) ||
              dataScadenza === null || !Number.isInteger(dataScadenza) ||
              dataScadenza < 0 || dataScadenza > 253402300799 ||
              typeof body.attivo !== "boolean") {
            return errorResponse("Dati dell'avviso non validi", corsHeaders, 400);
          }
          const idRecord = Number(body.id_riga);
          const resMod = await fetch(`${BASE_GRIST}/Avvisi/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Titolo": body.titolo.trim(), "Messaggio": body.messaggio.trim(), "Tipo": body.tipo_avviso, "Data_Scadenza": dataScadenza || null, "Attivo": body.attivo } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Avvisi" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // ==========================================
        // ENDPOINT ESISTENTI (INVARIATI)
        // ==========================================

        if (body.tipo === "get_presenze") {
          const date = parseCalendarDate(body.data);
          if (!date) return errorResponse("Data non valida", corsHeaders, 400);
          const filtroGrist = encodeURIComponent(JSON.stringify({ Data: [date.epochStart] }));
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
          const date = parseCalendarDate(body.data);
          if (!date || (body.id_riga !== undefined && body.id_riga !== null && !isRecordId(body.id_riga))) {
            return errorResponse("Data o ID assenza non validi", corsHeaders, 400);
          }
          const epochInizio = date.epochStart;
          const epochFine = epochInizio + 86399;
          
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

            let testoReport = `REPORT ANNUALE ASSENZE: TUTTI GLI ANNI (${Array.from(anniTrovati).sort().join(', ')})\n\n`;
            testoReport += `MOVIMENTI FERIE CUMULATI\n----------------------------------------\n`;
            testoReport += ` Ferie maturate (somma anni) : ${Math.round(tot_f_mat * 100) / 100} giorni\n`;
            testoReport += ` Ferie godute (vacanze reali) : ${Math.round(f_god * 100) / 100} giorni\n`;
            if (f_liq > 0.01) testoReport += ` Ferie liquidate/pagate     : ${Math.round(f_liq * 100) / 100} giorni\n`;
            if (f_ret > 0.01) testoReport += ` Rettifiche ferie (storni): ${Math.round(f_ret * 100) / 100} giorni\n\n\n`;
            testoReport += `MOVIMENTI PERMESSI CUMULATI\n----------------------------------------\n`;
            testoReport += ` Permessi maturati (somma anni) : ${Math.round(tot_p_mat * 100) / 100} ore\n`;
            testoReport += ` Permessi fruiti (ore assenza) : ${Math.round(p_god * 100) / 100} ore\n`;
            if (p_liq > 0.01) testoReport += ` Permessi liquidati/pagate  : ${Math.round(p_liq * 100) / 100} ore\n`;
            if (p_ret > 0.01) testoReport += ` Rettifiche permessi (storni): ${Math.round(p_ret * 100) / 100} ore\n\n\n`;
            testoReport += `MALATTIE CUMULATE\n----------------------------------------\n Giorni di malattia totali    : ${Math.round(malattia_tot * 100) / 100} giorni`;

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

          let testoReport = `REPORT ANNUALE ASSENZE: ANNO ${anno_rif}\n\n`;
          testoReport += `MOVIMENTI FERIE DELL'ANNO\n----------------------------------------\n`;
          testoReport += ` Residuo anno precedente    : ${partenza_ferie} giorni\n`;
          testoReport += ` Ferie maturate nell'anno   : ${ferie_contratto_anno} giorni\n`;
          testoReport += ` Ferie godute (vacanze reali) : ${Math.round(f_god * 100) / 100} giorni\n`;
          if (f_liq > 0.01) testoReport += ` Ferie liquidate/pagate     : ${Math.round(f_liq * 100) / 100} giorni\n`;
          if (f_ret > 0.01) testoReport += ` Rettifiche ferie (storni): ${Math.round(f_ret * 100) / 100} giorni\n`;
          testoReport += `\n Saldo ferie a fine anno    : ${saldo_ferie} giorni\n\n\n`;
          testoReport += `MOVIMENTI PERMESSI DELL'ANNO\n----------------------------------------\n`;
          testoReport += ` Residuo anno precedente    : ${partenza_permessi} ore\n`;
          testoReport += ` Permessi maturati nell'anno: ${permessi_contratto_anno} ore\n`;
          testoReport += ` Permessi fruiti (ore assenza) : ${Math.round(p_god * 100) / 100} ore\n`;
          if (p_liq > 0.01) testoReport += ` Permessi liquidati/pagati  : ${Math.round(p_liq * 100) / 100} ore\n`;
          if (p_ret > 0.01) testoReport += ` Rettifiche permessi (storni): ${Math.round(p_ret * 100) / 100} ore\n`;
          testoReport += `\n Saldo permessi a fine anno : ${saldo_permessi} ore\n\n\n`;
          testoReport += `MALATTIE DELL'ANNO\n----------------------------------------\n Giorni di malattia nell'anno : ${Math.round(malattia_anno * 100) / 100} giorni`;

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

            let testoReport = `REPORT MENSILE ASSENZE: ${mese.toUpperCase()} (TUTTI GLI ANNI: ${Array.from(anniTrovati).sort().join(', ')})\n\n`;
            testoReport += `MOVIMENTI FERIE DI QUESTO MESE\n----------------------------------------\n`;
            testoReport += ` Ferie maturate (somma anni) : ${Math.round(tot_mat_ferie * 100) / 100} giorni\n`;
            testoReport += ` Ferie godute (vacanze reali) : ${Math.round(f_god * 100) / 100} giorni\n`;
            if (f_liq > 0.01) testoReport += ` Ferie liquidate/pagate     : ${Math.round(f_liq * 100) / 100} giorni\n`;
            if (f_ret > 0.01) testoReport += ` Rettifiche ferie (storni): ${Math.round(f_ret * 100) / 100} giorni\n\n\n`;
            testoReport += `MOVIMENTI PERMESSI DI QUESTO MESE\n----------------------------------------\n`;
            testoReport += ` Permessi maturati (somma anni) : ${Math.round(tot_mat_permessi * 100) / 100} ore\n`;
            testoReport += ` Permessi fatti (ore assenza) : ${Math.round(p_god * 100) / 100} ore\n`;
            if (p_liq > 0.01) testoReport += ` Permessi liquidati/pagati  : ${Math.round(p_liq * 100) / 100} ore\n`;
            if (p_ret > 0.01) testoReport += ` Rettifiche permessi (storni): ${Math.round(p_ret * 100) / 100} ore\n\n\n`;
            testoReport += `MALATTIE DEL MESE\n----------------------------------------\n Giorni di malattia nel mese  : ${Math.round(mal_tot * 100) / 100} giorni`;

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

          let testoReport = `REPORT MENSILE ASSENZE: ${mese.toUpperCase()} ${anno_rif}\n\n`;
          testoReport += `MOVIMENTI FERIE DI QUESTO MESE\n----------------------------------------\n`;
          testoReport += ` Saldo mese precedente      : ${saldo_precedente_ferie} giorni\n`;
          testoReport += ` Ferie maturate nel mese    : ${coeff_ferie_mese} giorni\n`;
          testoReport += ` Ferie godute (vacanze reali) : ${Math.round(ferie_godute_mese * 100) / 100} giorni\n`;
          if (ferie_liquidate_mese > 0.01) testoReport += ` Ferie liquidate/pagate     : ${Math.round(ferie_liquidate_mese * 100) / 100} giorni\n`;
          if (ferie_rettificate_mese > 0.01) testoReport += ` Rettifiche ferie del mese: ${Math.round(ferie_rettificate_mese * 100) / 100} giorni\n`;
          testoReport += `\n Saldo ferie a fine mese    : ${saldo_reale_ferie_mese} giorni\n\n\n`;
          testoReport += `MOVIMENTI PERMESSI DI QUESTO MESE\n----------------------------------------\n`;
          testoReport += ` Saldo mese precedente      : ${saldo_precedente_permessi} ore\n`;
          testoReport += ` Permessi maturati nel mese : ${coeff_permessi_mese} ore\n`;
          testoReport += ` Permessi fatti (ore assenza) : ${Math.round(permessi_fatti_mese * 100) / 100} ore\n`;
          if (permessi_liquidati_mese > 0.01) testoReport += ` Permessi liquidati/pagati  : ${Math.round(permessi_liquidati_mese * 100) / 100} ore\n`;
          if (permessi_rettificati_mese > 0.01) testoReport += ` Rettifiche permessi mese : ${Math.round(permessi_rettificati_mese * 100) / 100} ore\n`;
          testoReport += `\n Saldo permessi a fine mese : ${saldo_reale_permessi_mese} ore\n\n\n`;
          testoReport += `MALATTIE DEL MESE\n----------------------------------------\n Giorni di malattia nel mese  : ${Math.round(malattia_mese * 100) / 100} giorni`;

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

          let testoReport = `REPORT TIMBRATURE: ${titoloPeriodo}\nPERIODO: ${titoloPeriodo}\n\n`;
          testoReport += `PRESENZE E GIORNATE\n----------------------------------------\n`;
          testoReport += ` Giorni lavorati completi   : ${giorniLavorati} giorni\n`;
          if (giorniCantiere > 0) testoReport += ` Giornate solo Cantiere     : ${giorniCantiere} giorni\n`;
          if (giorniIncompleti > 0) testoReport += ` Giornate incomplete      : ${giorniIncompleti} giorni\n`;
          testoReport += `\n Totale giorni registrati   : ${giorniLavorati + giorniCantiere} giorni\n\n\n`;

          testoReport += `CONTEGGIO ORE LAVORATE\n----------------------------------------\n`;
          testoReport += ` Ore nette lavorate totali  : ${formatOre(minutiLavoratiTotali)}\n`;
          testoReport += ` Ore pausa pranzo detratte  : ${formatOre(minutiPausaTotali)}\n`;
          testoReport += ` Ore straordinario (>8h/gg) : ${formatOre(minutiStraordinarioTotali)}\n`;
          testoReport += `\n Totale ore nette periodo   : ${(minutiLavoratiTotali / 60).toFixed(2).replace('.', ',')} ore`;

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
          const anno = parseFiniteNumber(body.anno);
          const mese = parseFiniteNumber(body.mese);
          const ferieResidue = parseFiniteNumber(ferieInput);
          const permessiResidui = parseFiniteNumber(permessiInput);
          if (!validInteger(anno, 1900, 9999) || !validInteger(mese, 1, 12) ||
              ferieResidue === null || Math.abs(ferieResidue) > 100000 ||
              permessiResidui === null || Math.abs(permessiResidui) > 100000) {
            return errorResponse("Dati della verifica busta paga non validi", corsHeaders, 400);
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
            return errorResponse("Errore aggiornamento della riga ID 1 in Verifica_Buste_Paga", corsHeaders, upstreamErrorStatus(response));
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
            festivita: "Festivita",
            verifica_buste_paga: "Verifica_Buste_Paga"
          };
          const tabellaId = typeof body.tabella === "string" && Object.hasOwn(tabelleEliminabili, body.tabella)
            ? tabelleEliminabili[body.tabella]
            : null;
          if (!tabellaId || !isRecordId(body.id_riga)) {
            return errorResponse("Tabella o ID record non valido", corsHeaders, 400);
          }
          const idRecord = Number(body.id_riga);

          const resElimina = await fetch(`${BASE_GRIST}/${tabellaId}/records/delete`, {
            method: "POST", headers: { ...headersGrist, "Content-Type": "application/json" },
            body: JSON.stringify([idRecord])
          });
          if (!resElimina.ok) return errorResponse("Errore durante l'eliminazione su Grist", corsHeaders, 500);
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        let tabellaId = "";
        let fields = {};
        const hasRecordId = body.id_riga !== undefined && body.id_riga !== null && body.id_riga !== "";
        if (hasRecordId && !isRecordId(body.id_riga)) {
          return errorResponse("ID record non valido", corsHeaders, 400);
        }
        const idRigaModifica = hasRecordId ? Number(body.id_riga) : null;
        const data = parseCalendarDate(body.data);
        const note = body.note;
        if (!data || !validString(note, 5000)) {
          return errorResponse("Data o note non valide", corsHeaders, 400);
        }

        if (body.tipo === "presenze") {
          const ore = parseFiniteNumber(body.ore);
          const minuti = parseFiniteNumber(body.minuti);
          if (!validString(body.evento, 100, false) ||
              !validInteger(ore, 0, 23) || !validInteger(minuti, 0, 59) ||
              (body.note_modifica !== undefined && !validString(body.note_modifica, 5000))) {
            return errorResponse("Dati della timbratura non validi", corsHeaders, 400);
          }
          const erroreRegole = await validateCalendarWrite(BASE_GRIST, headersGrist, data, "presenze", body, idRigaModifica);
          if (erroreRegole) return errorResponse(erroreRegole.error, corsHeaders, erroreRegole.status);
          tabellaId = "Prova";
          fields = {
            "Data": body.data,
            "Evento": body.evento,
            "Ora": String(ore).padStart(2, '0'),
            "Minuti": String(minuti).padStart(2, '0'),
            "Note": note
          };
        } else if (body.tipo === "registro") {
          const quantita = parseFiniteNumber(body.quantita);
          if (!validString(body.tipoAssenza, 100, false) ||
              !validInteger(quantita, 1, 8) ||
              (body.note_modifica !== undefined && !validString(body.note_modifica, 5000))) {
            return errorResponse("Dati dell'assenza non validi", corsHeaders, 400);
          }
          const erroreRegole = await validateCalendarWrite(BASE_GRIST, headersGrist, data, "registro", body, idRigaModifica);
          if (erroreRegole) return errorResponse(erroreRegole.error, corsHeaders, erroreRegole.status);
          tabellaId = "Registro_Ferie_Permessi";
          fields = {
            "Data": body.data,
            "Tipo_Assenza": body.tipoAssenza,
            "Quantita": quantita,
            "Note": note
          };
        } else {
          return errorResponse("Tipo richiesta non riconosciuto", corsHeaders, 400);
        }

        if (idRigaModifica !== null) {
          fields["Ultima_Modifica"] = Math.floor(Date.now() / 1000);
          fields["Note_Modifica"] = body.note_modifica || "Modificato da pannello gestionale";
        }

        const metodoHTTP = idRigaModifica !== null ? "PATCH" : "POST";
        const payloadGrist = idRigaModifica !== null
          ? { records: [{ id: idRigaModifica, fields }] }
          : { records: [{ fields }] };

        const response = await fetch(`${BASE_GRIST}/${tabellaId}/records`, {
          method: metodoHTTP,
          headers: { "Content-Type": "application/json", ...headersGrist },
          body: JSON.stringify(payloadGrist)
        });

        if (!response.ok) return errorResponse("Errore durante il salvataggio su Grist", corsHeaders, 500);
        const result = await response.json();
        return new Response(JSON.stringify({ success: true, data: result }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

      } catch (error) {
        console.error("Errore interno del Worker", error);
        return errorResponse("Errore interno del server", corsHeaders, 500);
      }
    }

    if (request.method === "GET") {
      return errorResponse("Endpoint non riconosciuto", corsHeaders, 404);
    }
    return errorResponse("Metodo non consentito", corsHeaders, 405);
  }
};