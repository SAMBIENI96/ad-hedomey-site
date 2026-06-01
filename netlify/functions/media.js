const { getStore } = require('@netlify/blobs');

const mediaStore = getStore('ad-hedomey-media');

function headers(extraHeaders = {}) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'public, max-age=31536000, immutable',
    ...extraHeaders
  };
}

exports.handler = async (event) => {
  try {
    const key = event.queryStringParameters?.key || '';

    if (!key || key.includes('..') || key.startsWith('/')) {
      return { statusCode: 400, headers: headers({ 'Content-Type': 'text/plain; charset=utf-8' }), body: 'Fichier invalide.' };
    }

    const result = await mediaStore.getWithMetadata(key, { type: 'arrayBuffer' });

    if (!result || !result.data) {
      return { statusCode: 404, headers: headers({ 'Content-Type': 'text/plain; charset=utf-8' }), body: 'Fichier introuvable.' };
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
    return { statusCode: 500, headers: headers({ 'Content-Type': 'text/plain; charset=utf-8' }), body: 'Erreur serveur.' };
  }
};
