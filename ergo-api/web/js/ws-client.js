// Shared dashboard WebSocket helper for `/api/v1/ws` channel subscriptions.
// One socket per call site; exponential reconnect while `start()`ed.

export function wsUrl() {
  const u = new URL('/api/v1/ws', window.location.href);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  return u;
}

/**
 * @param {{
 *   channels: string[],
 *   id?: string,
 *   onEvent?: (frame: object) => void,
 *   onOpen?: () => void,
 *   onClose?: () => void,
 * }} opts
 */
export function createChannelSub(opts) {
  const channels = opts.channels || [];
  const subId = opts.id || `sub-${channels.join('-') || 'none'}`;
  let socket = null;
  let retryTimer = null;
  let retryMs = 1000;
  let connected = false;
  let stopped = true;

  function scheduleReconnect() {
    if (stopped || retryTimer) return;
    const delay = retryMs;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      connect();
    }, delay);
    retryMs = Math.min(30_000, retryMs * 2);
  }

  function connect() {
    if (stopped || socket || typeof WebSocket === 'undefined') return;
    const ws = new WebSocket(wsUrl());
    socket = ws;
    ws.addEventListener('open', () => {
      connected = true;
      retryMs = 1000;
      if (channels.length) {
        ws.send(JSON.stringify({ op: 'subscribe', id: subId, channels }));
      }
      if (opts.onOpen) opts.onOpen();
    });
    ws.addEventListener('message', (ev) => {
      if (!opts.onEvent) return;
      try {
        opts.onEvent(JSON.parse(ev.data));
      } catch {
        /* ignore malformed frames */
      }
    });
    ws.addEventListener('close', () => {
      // Ignore close from a socket that `stop()`/`connect()` already replaced.
      if (socket !== ws) return;
      socket = null;
      connected = false;
      if (opts.onClose) opts.onClose();
      scheduleReconnect();
    });
    ws.addEventListener('error', () => {
      ws.close();
    });
  }

  return {
    start() {
      if (socket || retryTimer) {
        stopped = false;
        return;
      }
      stopped = false;
      connect();
    },
    stop() {
      stopped = true;
      connected = false;
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      const ws = socket;
      socket = null;
      if (ws) ws.close();
    },
    isConnected() {
      return connected;
    },
  };
}
