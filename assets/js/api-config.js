(function () {
  function resolveApiBaseUrl() {
    if (window.location.protocol === "file:") {
      return "http://localhost:5500";
    }

    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      return window.location.port === "5500"
        ? window.location.origin
        : `${window.location.protocol}//${host}:5500`;
    }

    return window.location.origin;
  }

  window.API_BASE_URL = resolveApiBaseUrl();

  window.apiFetch = async function apiFetch(path, options) {
    const response = await fetch(`${window.API_BASE_URL}${path}`, options);
    let payload = null;

    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }

    if (!response.ok) {
      const message = payload?.error || payload?.message || `Request failed (${response.status})`;
      throw new Error(message);
    }

    return payload;
  };
})();
