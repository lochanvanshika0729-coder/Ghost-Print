/* Replace the local service with a FastAPI base URL by setting
   window.GHOSTGUARD_API_BASE before this file loads. */
(() => {
  let base = String(window.GHOSTGUARD_API_BASE || '').replace(/\/$/, '');
  async function request(path, options = {}) {
    const response = await fetch(`${base}${path}`, options);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Request failed (${response.status})`);
    }
    return response.json();
  }
  const qs = (values) => new URLSearchParams(Object.entries(values).filter(([, v]) => v !== '' && v != null)).toString();
  window.GhostguardAPI = {
    health: () => request('/api/health'),
    dashboard: () => request('/api/dashboard/summary'),
    forensics: () => request('/api/forensics/aggregate'),
    requests: (filters = {}) => request(`/api/investigations?${qs(filters)}`),
    audit: (id) => request(`/api/investigations/${encodeURIComponent(id)}`),
    identity: (id) => request(`/api/investigations/${encodeURIComponent(id)}/identity`),
    findings: (id) => request(`/api/investigations/${encodeURIComponent(id)}/findings`),
    aiExplain: (id) => request(`/api/investigations/${encodeURIComponent(id)}/ai-explanation`, { method: 'POST' }),
    remediation: (id) => request(`/api/investigations/${encodeURIComponent(id)}/remediation`),
    verification: (id) => request(`/api/investigations/${encodeURIComponent(id)}/verification`),
    lineage: (id) => request(`/api/investigations/${encodeURIComponent(id)}/graph`),
    risks: (id) => request(id ? `/api/investigations/${encodeURIComponent(id)}/risks` : '/api/risk-analysis'),
    certificate: (id) => request(`/api/investigations/${encodeURIComponent(id)}/certificate`),
    datasets: () => request('/api/datasets/official-challenge'),
    exportUrl: () => `${base}/api/reports/export`,
    configureBase(url) { base = String(url || '').replace(/\/$/, ''); window.GHOSTGUARD_API_BASE = base; }
  };
})();
