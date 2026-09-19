import { decryptLink } from '../decrypt.js';

self.onmessage = async ({ data }) => {
  try { self.postMessage({ url: await decryptLink(data) }); }
  catch (error) { self.postMessage({ error: error.message }); }
};
