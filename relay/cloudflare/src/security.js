// Security and token validation utilities for OmniTerminal Free Relay.
// Enforces constant-time string equality, identifier format validation, and bounded JSON payloads.
// Accepts generated UUID/256-bit hexadecimal tokens or a strong password.
// Format checks do not measure entropy: generate tokens with a secure RNG.

export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = new TextEncoder().encode(a);
  const bufB = new TextEncoder().encode(b);
  if (bufA.byteLength !== bufB.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < bufA.byteLength; i++) {
    diff |= bufA[i] ^ bufB[i];
  }
  return diff === 0;
}

export function scopeId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

const UUID_HYPHENATED_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UUID_HEX_REGEX = /^[0-9a-f]{32}$/i;
const RANDOM_TOKEN_HEX_REGEX = /^[0-9a-f]{64}$/i;

export function isUuid(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  return UUID_HYPHENATED_REGEX.test(trimmed) || UUID_HEX_REGEX.test(trimmed);
}

export function isStrongPassword(value) {
  if (typeof value !== 'string') return false;
  if (/[\s\x00-\x1f\x7f]/.test(value)) return false;
  const trimmed = value.trim();
  if (trimmed.length < 10 || trimmed.length > 256) return false;
  return (
    /[a-z]/.test(trimmed) &&
    /[A-Z]/.test(trimmed) &&
    /[0-9]/.test(trimmed) &&
    /[^A-Za-z0-9]/.test(trimmed)
  );
}

export function validateRelayToken(token) {
  if (typeof token !== 'string' || token.trim().length === 0) {
    return 'Relay token cannot be empty.';
  }
  if (/[\s\x00-\x1f\x7f]/.test(token)) {
    return 'Relay token cannot contain whitespace, newlines, or control characters.';
  }
  const trimmed = token.trim();
  if (isUuid(trimmed) || RANDOM_TOKEN_HEX_REGEX.test(trimmed)) {
    return null;
  }
  if (trimmed.length < 10) {
    return 'Relay token must be a UUID or at least 10 characters long.';
  }
  if (trimmed.length > 256) {
    return 'Relay token cannot exceed 256 characters.';
  }
  const missing = [];
  if (!/[a-z]/.test(trimmed)) missing.push('lowercase letter');
  if (!/[A-Z]/.test(trimmed)) missing.push('uppercase letter');
  if (!/[0-9]/.test(trimmed)) missing.push('number');
  if (!/[^A-Za-z0-9]/.test(trimmed)) missing.push('special character');

  if (missing.length > 0) {
    return `Relay token must be a UUID or a strong password containing: ${missing.join(', ')}.`;
  }
  return null;
}

export function isValidRelayToken(token) {
  return validateRelayToken(token) === null;
}

export function equalBytes(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export async function readBoundedJson(request, maxBytes = 16 * 1024, timeoutMs = 5000) {
  if (request.headers?.get) {
    const rawCl = request.headers.get('content-length');
    if (rawCl !== null && rawCl !== undefined) {
      const trimmed = rawCl.trim();
      // Must be non-empty sequence of digits only
      if (!/^\d+$/.test(trimmed)) {
        return { ok: false, error: 'invalid_content_length', status: 400 };
      }
      const parsedCl = Number(trimmed);
      if (!Number.isSafeInteger(parsedCl) || parsedCl < 0) {
        return { ok: false, error: 'invalid_content_length', status: 400 };
      }
      if (parsedCl > maxBytes) {
        return { ok: false, error: 'payload_too_large', status: 413 };
      }
    }
  }

  // Handle stream reader if present
  if (request.body && typeof request.body.getReader === 'function') {
    const reader = request.body.getReader();
    let timer = null;
    let timedOut = false;

    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        const err = new Error('request_timeout');
        err.status = 408;
        reject(err);
      }, timeoutMs);
    });

    let bytesCount = 0;
    const chunks = [];

    try {
      while (true) {
        const readResult = await Promise.race([reader.read(), timeoutPromise]);
        const { done, value } = readResult;
        if (done) break;
        if (value) {
          bytesCount += value.byteLength;
          if (bytesCount > maxBytes) {
            await reader.cancel('payload_too_large').catch(() => {});
            return { ok: false, error: 'payload_too_large', status: 413 };
          }
          chunks.push(value);
        }
      }
    } catch (err) {
      await reader.cancel(err).catch(() => {});
      if (timedOut || err?.message === 'request_timeout' || err?.status === 408) {
        return { ok: false, error: 'request_timeout', status: 408 };
      }
      if (err?.name === 'AbortError' || err?.message?.includes('abort')) {
        return { ok: false, error: 'request_aborted', status: 400 };
      }
      return { ok: false, error: 'read_error', status: 400 };
    } finally {
      if (timer) clearTimeout(timer);
    }

    const total = new Uint8Array(bytesCount);
    let offset = 0;
    for (const chunk of chunks) {
      total.set(chunk, offset);
      offset += chunk.byteLength;
    }

    let decoded;
    try {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      decoded = decoder.decode(total);
    } catch {
      return { ok: false, error: 'invalid_utf8', status: 400 };
    }

    try {
      const value = JSON.parse(decoded);
      return { ok: true, value };
    } catch {
      return { ok: false, error: 'invalid_json', status: 400 };
    }
  }

  // Fallback for requests without body stream or text() method
  if (typeof request.text === 'function') {
    let body;
    try {
      body = await request.text();
    } catch {
      return { ok: false, error: 'read_error', status: 400 };
    }
    const encoded = new TextEncoder().encode(body);
    if (encoded.length > maxBytes) {
      return { ok: false, error: 'payload_too_large', status: 413 };
    }
    try {
      const value = JSON.parse(body);
      return { ok: true, value };
    } catch {
      return { ok: false, error: 'invalid_json', status: 400 };
    }
  }

  return { ok: false, error: 'invalid_json', status: 400 };
}
