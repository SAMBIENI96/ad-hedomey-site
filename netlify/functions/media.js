let mediaStorePromise;
let blobsModulePromise;

async function getMediaStore(event) {
  if (!blobsModulePromise) {
    blobsModulePromise = import('@netlify/blobs');
  }

  const { connectLambda, getStore } = await blobsModulePromise;
  if (event && typeof connectLambda === 'function') {
    connectLambda(event);
  }

  if (!mediaStorePromise) {
    mediaStorePromise = Promise.resolve(getStore('ad-hedomey-media'));
  }

  return mediaStorePromise;
}

function headers(extraHeaders = {}, cacheControl = 'public, max-age=31536000, immutable') {
  return {
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': cacheControl,
    ...extraHeaders
  };
}

function mediaKey(event) {
  const queryKey = event.queryStringParameters?.key || '';
  if (queryKey && queryKey !== ':splat') return queryKey;

  const splat = event.pathParameters?.splat || '';
  if (splat) return splat;

  const path = event.path || '';
  const marker = '/.netlify/functions/media/';
  const markerIndex = path.indexOf(marker);
  if (markerIndex >= 0) return path.slice(markerIndex + marker.length);

  const uploadsMarker = '/uploads/';
  const uploadsIndex = path.indexOf(uploadsMarker);
  if (uploadsIndex >= 0) return path.slice(uploadsIndex + uploadsMarker.length);

  return '';
}

exports.handler = async (event) => {
  try {
    const key = mediaKey(event);

    if (!key || key.includes('..') || key.startsWith('/')) {
      return { statusCode: 400, headers: headers({ 'Content-Type': 'text/plain; charset=utf-8' }, 'no-store'), body: 'Fichier invalide.' };
    }

    const mediaStore = await getMediaStore(event);
    const result = await mediaStore.getWithMetadata(key, { type: 'arrayBuffer' });

    if (!result || !result.data) {
      return { statusCode: 404, headers: headers({ 'Content-Type': 'text/plain; charset=utf-8' }, 'no-store'), body: 'Fichier introuvable.' };
    }

    const buffer = Buffer.from(result.data);
    const contentType = result.metadata?.contentType || 'application/octet-stream';

    return {
      statusCode: 200,
      headers: headers({ 'Content-Type': contentType }),
      body: buffer.toString('base64'),
      isBase64Encoded: true
    };
  } catch (error) {
    console.error(error);
    return { statusCode: 500, headers: headers({ 'Content-Type': 'text/plain; charset=utf-8' }, 'no-store'), body: 'Erreur serveur.' };
  }
};
