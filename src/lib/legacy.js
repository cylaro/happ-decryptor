/**
 * Legacy (crypt–crypt4) encryption — inverse of the RSA block decryptor in
 * src/decrypt.js. Wraps any URL back into happ://crypt…/ links.
 */

import forge from 'node-forge';
import { PKCS1_KEYS_B64, decryptCrypt1to4, loadForgeKey } from '../decrypt.js';

const SCHEMES = ['crypt', 'crypt2', 'crypt3', 'crypt4'];

export const decryptCryptLegacy = decryptCrypt1to4;

function textToLatinBytes(text) {
  return new TextEncoder().encode(text);
}

function latinBytesToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

/**
 * Encrypt a URL with the hardcoded generation key: block-wise RSA-PKCS1v15,
 * matching the app's own layout. ordinal: 0=crypt … 3=crypt4.
 */
export function encryptCryptLegacy(ordinal, target) {
  if (ordinal < 0 || ordinal >= SCHEMES.length) throw new Error(`unknown legacy scheme: ${ordinal}`);

  const privateKey = loadForgeKey(PKCS1_KEYS_B64[ordinal], 'RSA PRIVATE KEY');
  const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
  const keySize = Math.ceil(privateKey.n.bitLength() / 8);
  const maxBlock = keySize - 11;

  const bytes = textToLatinBytes(target);
  let cipherBinary = '';
  for (let i = 0; i < bytes.length; i += maxBlock) {
    const chunk = bytes.subarray(i, i + maxBlock);
    let message = '';
    for (let j = 0; j < chunk.length; j++) message += String.fromCharCode(chunk[j]);
    cipherBinary += publicKey.encrypt(message, 'RSAES-PKCS1-V1_5');
  }

  const cipherBytes = new Uint8Array(cipherBinary.length);
  for (let i = 0; i < cipherBinary.length; i++) cipherBytes[i] = cipherBinary.charCodeAt(i) & 0xff;

  return `happ://${SCHEMES[ordinal]}/${latinBytesToB64(cipherBytes)}`;
}
