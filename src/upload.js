// Single-file uploader: init → presigned PUTs straight to R2 → complete.
//
// This is a Node port of public/upload-core.js in the stickr repo — the one
// uploader behind every browser upload surface. The retry, chunking, and
// presign-continuation logic is the same code with the same constants and
// function names: apiFetch treats a 429 as a pause (Retry-After, seconds or
// HTTP-date, capped at one window; else full-jitter backoff), the chunk pool
// is 5 workers wide with single-flight presign continuation past the first
// 100 URLs, each PUT gets 3 tries, each etag report gets 3 tries, and
// complete's downloadUrl is authoritative. A change to any of that here
// needs a look at upload-core.js, and vice versa: the browser copies of this
// logic diverged into real bugs three times before they were unified, and a
// port one repo over carries exactly that risk.
//
// Deliberate differences, all at the edges:
//   - chunks come from positional reads on one file descriptor, never a
//     whole-file buffer (a 10 GB push must not hold 10 GB);
//   - the PUT is fetch with a Buffer body, so progress advances per completed
//     chunk (undici has no upload-progress events);
//   - every API call carries the base URL and the bearer;
//   - the file-level pool (FILE_CONCURRENCY) is not ported — push is one
//     file per call, so there is nothing to parallelise at that layer;
//   - no resume: a failed push restarts from the beginning and the server
//     sweeps the orphaned session.
import { open } from 'node:fs/promises';

var RETRY_MAX_ATTEMPTS = 5;
var RETRY_BASE_MS = 1000;
var RETRY_BACKOFF_CAP_MS = 30000;
var RETRY_AFTER_CAP_MS = 60000; // one rate-limit window; anything longer is a broken header
var RETRY_POLL_MS = 100;
var CONCURRENCY = 5;

export class UploadError extends Error {}

function retryAfterMs(res) {
  var h = res.headers && res.headers.get ? res.headers.get('Retry-After') : null;
  if (!h) return null;
  var secs = Number(h);
  if (isFinite(secs) && secs >= 0) return Math.min(secs * 1000, RETRY_AFTER_CAP_MS);
  var at = Date.parse(h);
  if (!isNaN(at)) return Math.min(Math.max(0, at - Date.now()), RETRY_AFTER_CAP_MS);
  return null;
}
async function sleepUnless(ms, shouldStop) {
  var until = Date.now() + ms;
  while (Date.now() < until) {
    if (shouldStop()) return false;
    await new Promise(function (r) { setTimeout(r, Math.min(RETRY_POLL_MS, until - Date.now())); });
  }
  return !shouldStop();
}

// API fetch with 429 handling, shared by init, presign, complete and the
// portal list. Resolves to the Response (ok, a non-429 error, or the final
// 429 once attempts run out), or null when shouldStop() went true. Network
// errors reject like plain fetch. `client` is { baseUrl, token }.
export async function apiFetch(client, path, init, shouldStop) {
  shouldStop = shouldStop || function () { return false; };
  init = init || {};
  var headers = Object.assign({}, init.headers || {}, { Authorization: 'Bearer ' + client.token });
  var res = null;
  for (var attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
    if (shouldStop()) return null;
    res = await fetch(client.baseUrl + path, Object.assign({}, init, { headers }));
    if (res.status !== 429) return res;
    if (attempt === RETRY_MAX_ATTEMPTS - 1) break;
    var wait = retryAfterMs(res);
    if (wait === null) wait = Math.random() * Math.min(RETRY_BACKOFF_CAP_MS, RETRY_BASE_MS * Math.pow(2, attempt));
    if (!(await sleepUnless(wait, shouldStop))) return null;
  }
  return res;
}

// PUT one chunk to a presigned R2 URL. Resolves { etag }.
async function uploadToR2(presignedUrl, buf) {
  var res = await fetch(presignedUrl, { method: 'PUT', body: buf });
  await res.arrayBuffer().catch(function () {});
  if (res.status >= 200 && res.status < 300) return { etag: (res.headers.get('ETag') || '').replace(/"/g, '') };
  throw new Error('Upload failed: ' + res.status);
}

// Upload one file. opts:
//   client      — { baseUrl, token }
//   filePath    — absolute path (already vetted by safety.js)
//   name, size  — basename and byte length
//   mimeType
//   portalToken — 8-char portal token
//   onProgress  — optional function({ sent, total, pct })
//   signal      — optional AbortSignal; checked between chunks and before
//                 each API call. A cancelled upload stops cleanly and never
//                 finalizes.
// Resolves { url, name, size }; throws UploadError with a user-facing
// message (the same strings the browser shows), or a plain Error on abort.
export async function uploadFile(opts) {
  var client = opts.client;
  var onProgress = opts.onProgress || function () {};
  var signal = opts.signal;
  function isCancelled() { return !!(signal && signal.aborted); }

  var initRes = await apiFetch(client, '/api/big/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      files: [{ filename: opts.name, fileSize: opts.size, mimeType: opts.mimeType }],
      portalToken: opts.portalToken,
    }),
  }, isCancelled);
  if (!initRes) throw new Error('cancelled');
  if (!initRes.ok) {
    var err = await initRes.json().catch(function () { return {}; });
    throw new UploadError(err.error || ('init failed: HTTP ' + initRes.status));
  }
  var data = await initRes.json();
  var sess = data.sessions[0];

  var fh = await open(opts.filePath, 'r');
  try {
    // Presigned URLs keyed by chunk index. Init returns the first 100 as an
    // array; the presign continuation endpoint returns an OBJECT keyed by
    // absolute chunk index (the next window of chunks with no reported etag).
    var presignedUrls = {};
    for (var pi = 0; pi < sess.presignedUrls.length; pi++) presignedUrls[pi] = sess.presignedUrls[pi];
    var chunkSize = sess.chunkSize;
    var chunkProgress = new Float64Array(sess.totalChunks);
    var uploadFailed = false;
    var failMessage = '';
    var fetchingMoreUrls = false;
    function aborted() { return uploadFailed || isCancelled(); }
    function reportProgress() {
      var sent = 0;
      for (var c = 0; c < sess.totalChunks; c++) sent += chunkProgress[c];
      onProgress({ sent: sent, total: opts.size, pct: Math.min(Math.round((sent / opts.size) * 100), 100) });
    }

    // Single-flight presign continuation: one worker fetches the next
    // 100-URL window, the rest wait on it instead of stampeding.
    async function ensurePresignedUrl(chunkIndex) {
      if (presignedUrls[chunkIndex]) return;
      if (fetchingMoreUrls) {
        while (!presignedUrls[chunkIndex] && !uploadFailed && fetchingMoreUrls) {
          await new Promise(function (r) { setTimeout(r, 100); });
        }
        if (presignedUrls[chunkIndex] || uploadFailed) return;
        // fetch ended without our URL — fall through and try ourselves
      }
      fetchingMoreUrls = true;
      try {
        var presignRes = await apiFetch(client, '/api/big/presign/' + sess.sessionId, {
          method: 'POST',
          headers: { 'X-Upload-Secret': sess.uploadSecret },
        }, aborted);
        if (presignRes && presignRes.ok) {
          var presignData = await presignRes.json();
          for (var k in presignData.presignedUrls) presignedUrls[k] = presignData.presignedUrls[k];
        } else if (presignRes) {
          var perr = await presignRes.json().catch(function () { return {}; });
          uploadFailed = true;
          failMessage = 'could not get upload URLs: ' + (perr.error || ('HTTP ' + presignRes.status));
        }
        // null = cancelled mid-wait; the caller's aborted() check handles it
      } catch (pe) {
        uploadFailed = true;
        failMessage = 'could not get upload URLs: ' + pe.message;
      }
      fetchingMoreUrls = false;
    }

    async function uploadOneChunk(i) {
      if (aborted()) return;
      await ensurePresignedUrl(i);
      if (aborted()) return;
      if (!presignedUrls[i]) { uploadFailed = true; failMessage = 'could not get upload URLs — try again'; return; }
      var start = i * chunkSize;
      var end = Math.min(start + chunkSize, opts.size);
      var buf = Buffer.allocUnsafe(end - start);
      var rd = await fh.read(buf, 0, end - start, start);
      if (rd.bytesRead !== end - start) { uploadFailed = true; failMessage = 'file changed while uploading'; return; }

      var retries = 3;
      var chunkResult = null;
      while (retries > 0) {
        if (uploadFailed) return;
        try {
          chunkResult = await uploadToR2(presignedUrls[i], buf);
          chunkProgress[i] = end - start;
          reportProgress();
          break;
        } catch (err) {
          retries--;
          if (retries === 0) { uploadFailed = true; failMessage = 'upload failed: ' + err.message; return; }
          await new Promise(function (r) { setTimeout(r, 2000); });
        }
      }
      if (uploadFailed) return;

      // Report etag — awaited inside this worker (other workers' PUTs
      // overlap the round trip) and verified with retries: a missed etag
      // means a failed multipart assembly at /complete.
      var reportRetries = 3;
      while (reportRetries > 0) {
        try {
          var rr = await fetch(client.baseUrl + '/api/big/report-etag/' + sess.sessionId, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Upload-Secret': sess.uploadSecret },
            body: JSON.stringify({ chunkIndex: i, etag: chunkResult.etag }),
          });
          await rr.arrayBuffer().catch(function () {});
          if (!rr.ok) throw new Error('report failed');
          break;
        } catch (e2) {
          reportRetries--;
          if (reportRetries === 0) { uploadFailed = true; failMessage = 'failed to register chunk — try again'; return; }
          await new Promise(function (r) { setTimeout(r, 1000); });
        }
      }
    }

    var nextChunk = 0;
    async function poolWorker() {
      while (nextChunk < sess.totalChunks && !aborted()) {
        var myChunk = nextChunk++;
        await uploadOneChunk(myChunk);
      }
    }
    var workers = [];
    for (var w = 0; w < Math.min(CONCURRENCY, sess.totalChunks); w++) workers.push(poolWorker());
    await Promise.all(workers);

    if (isCancelled()) throw new Error('cancelled');
    if (uploadFailed) throw new UploadError(failMessage || 'upload failed');

    // Complete — reached only after every worker drained, so the server has
    // the full etag map for multipart assembly. A cancel during a 429
    // backoff returns null here: the file is never finalized late.
    var completeRes = await apiFetch(client, '/api/big/complete/' + sess.sessionId, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Upload-Secret': sess.uploadSecret },
    }, aborted);
    if (!completeRes) throw new Error('cancelled');
    if (!completeRes.ok) {
      var cerr = await completeRes.json().catch(function () { return {}; });
      throw new UploadError('could not finalize ' + opts.name + (cerr.error ? ': ' + cerr.error : ''));
    }
    // Complete's downloadUrl is the authoritative share link; fall back to
    // the init download token only if this body didn't parse.
    var url = null;
    try {
      var completeData = await completeRes.json();
      if (completeData && completeData.downloadUrl) url = completeData.downloadUrl;
    } catch {}
    if (!url && sess.downloadToken) url = client.baseUrl + '/big/dl/' + sess.downloadToken;
    if (!url) throw new UploadError('upload finished but no link came back');
    return { url: url, name: opts.name, size: opts.size };
  } finally {
    await fh.close().catch(function () {});
  }
}
