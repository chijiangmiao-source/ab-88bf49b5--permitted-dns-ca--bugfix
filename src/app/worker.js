/**
 * Verification worker. All DER parsing, WebCrypto key imports and signature
 * checks run off the main thread; the UI only renders the returned report.
 *
 * Protocol:
 *   main -> worker : { type: 'verify', payload: {...} , requestId }
 *   worker -> main : { type: 'result', requestId, report }
 *                     { type: 'error', requestId, message }
 */

import { verifyChain } from './crypto/verifier.js';

self.onmessage = async (ev) => {
  const msg = ev.data;
  if (!msg || msg.type !== 'verify') return;
  const { requestId, payload } = msg;
  try {
    const report = await verifyChain(payload);
    self.postMessage({ type: 'result', requestId, report });
  } catch (e) {
    self.postMessage({
      type: 'error',
      requestId,
      message: e && e.message ? e.message : String(e),
      stack: e && e.stack ? e.stack : undefined,
    });
  }
};
