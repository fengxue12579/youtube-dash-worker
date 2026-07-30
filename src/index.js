import { Innertube, UniversalCache } from 'youtubei.js';

// 密钥配置：用于签名和验证媒体代理 URL 的 Token (需与输入依赖的 TOKEN 校验保持一致)
const SECRET = 'Forward-YouTube-Worker-Secret-Key';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    try {
      // 路由 1: 获取 DASH Manifest 清单
      // 匹配模式: /dash/:videoId/manifest.mpd 或 /dash/:videoId
      const dashMatch = pathname.match(/^\/dash\/([A-Za-z0-9_-]{11})(?:\/manifest\.mpd)?$/);
      if (dashMatch) {
        const videoId = dashMatch[1];
        return await handleDashManifest(videoId, url.origin);
      }

      // 路由 2: 音视频切片代理转发 (转发分轨音视频数据)
      // 匹配模式: /media?token=...
      if (pathname === '/media' || pathname === '/media/') {
        const token = url.searchParams.get('token');
        if (!token) {
          return new Response('Missing media token', { status: 400 });
        }
        return await handleMediaProxy(token, request);
      }

      // 默认 404
      return new Response('Not Found', { status: 404 });
    } catch (err) {
      console.error('Worker Error:', err);
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};

/**
 * 1. 处理 DASH Manifest 生成
 */
async function handleDashManifest(videoId, origin) {
  // 初始化 InnerTube (YouTube.js)
  const yt = await Innertube.create({
    cache: new UniversalCache(false),
    generate_session_locally: true,
  });

  // 获取视频播放数据
  const info = await yt.getBasicInfo(videoId);

  // 转换视频/音频源的 URL 为 Worker 代理 URL，避免直连产生跨域或签名失效
  const urlTransformer = async (upstreamUrl) => {
    const rawUrl = upstreamUrl.toString();
    const token = await createMediaToken(rawUrl, SECRET);
    return `${origin}/media?token=${encodeURIComponent(token)}`;
  };

  // 调用 YouTube.js 的 toDash 模块生成 DASH 清单
  const mpdManifest = await info.toDash(urlTransformer);

  return new Response(mpdManifest, {
    status: 200,
    headers: {
      'Content-Type': 'application/dash+xml',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

/**
 * 2. 处理音视频分轨代理请求
 */
async function handleMediaProxy(token, request) {
  let targetUrl;
  try {
    // 校验 Token 规范与签名，提取上游 googlevideo.com URL
    targetUrl = await verifyMediaToken(token, SECRET);
  } catch (e) {
    return new Response(`Token Verification Failed: ${e.message}`, { status: 403 });
  }

  // 构建转发给 YouTube 音视频服务器的请求头
  const headers = new Headers(request.headers);
  headers.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
  headers.set('Referer', 'https://www.youtube.com/');
  headers.set('Origin', 'https://www.youtube.com');
  headers.delete('Host');

  // 请求上游音频/视频切片
  const response = await fetch(targetUrl, {
    method: request.method,
    headers: headers,
  });

  // 返回响应并添加 CORS 跨域允许信息
  const responseHeaders = new Headers(response.headers);
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

/* =========================================================================
   Token 加密 / 解密校验函数 (完全适配你提供的 Source 1 逻辑)
   ========================================================================= */

const TOKEN_VERSION = 1;
const DEFAULT_TOKEN_LIFETIME_SECONDS = 3 * 60 * 60;
const EXPIRY_SAFETY_MARGIN_SECONDS = 60;

async function createMediaToken(mediaUrl, secret, now = Date.now, metadata = {}) {
  const url = validateMediaUrl(mediaUrl);
  const payload = {
    version: TOKEN_VERSION,
    expiresAt: readTokenExpiry(url, now()),
    url: url.toString(),
    ...metadata,
  };
  const encodedPayload = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await sign(encodedPayload, secret);
  return `${encodedPayload}.${encodeBase64Url(signature)}`;
}

async function verifyMediaToken(token, secret, now = Date.now) {
  const payload = await verifyMediaTokenPayload(token, secret, now);
  return payload.url;
}

async function verifyMediaTokenPayload(token, secret, now = Date.now) {
  const [encodedPayload, encodedSignature, extraPart] = String(token).split('.');
  if (!encodedPayload || !encodedSignature || extraPart) {
    throw new Error('Invalid media token');
  }
  const key = await importSigningKey(secret);
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    decodeBase64Url(encodedSignature),
    new TextEncoder().encode(encodedPayload)
  );
  if (!valid) {
    throw new Error('Invalid media token signature');
  }
  const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(encodedPayload)));
  if (
    payload.version !== TOKEN_VERSION ||
    !Number.isFinite(payload.expiresAt) ||
    payload.expiresAt <= Math.floor(now() / 1e3)
  ) {
    throw new Error('Expired media token');
  }
  return {
    ...payload,
    url: validateMediaUrl(payload.url).toString(),
  };
}

function readTokenExpiry(url, nowMs) {
  const nowSeconds = Math.floor(nowMs / 1e3);
  const defaultExpiry = nowSeconds + DEFAULT_TOKEN_LIFETIME_SECONDS;
  const upstreamExpiry = Number(url.searchParams.get('expire'));
  if (!Number.isFinite(upstreamExpiry)) {
    return defaultExpiry;
  }
  return Math.min(defaultExpiry, upstreamExpiry - EXPIRY_SAFETY_MARGIN_SECONDS);
}

function validateMediaUrl(value) {
  const url = new URL(value);
  const hostname = url.hostname.toLowerCase();
  if (
    url.protocol !== 'https:' ||
    (hostname !== 'googlevideo.com' && !hostname.endsWith('.googlevideo.com'))
  ) {
    throw new Error('Media token contains a disallowed upstream');
  }
  return url;
}

async function sign(value, secret) {
  const key = await importSigningKey(secret);
  return new Uint8Array(
    await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value))
  );
}

function importSigningKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(secret)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function encodeBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64Url(value) {
  const standard = String(value).replace(/-/g, '+').replace(/_/g, '/');
  const padded = standard.padEnd(standard.length + ((4 - (standard.length % 4)) % 4), '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
