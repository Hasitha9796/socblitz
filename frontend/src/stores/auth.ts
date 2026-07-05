// ─── Auth store (Zustand) ─────────────────────────────────────────────────────
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  token:     string | null
  userId:    string | null
  role:      string | null
  fullName:  string | null
  setAuth:   (token: string, userId: string, role: string, fullName: string) => void
  clearAuth: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token:     null,
      userId:    null,
      role:      null,
      fullName:  null,
      setAuth:   (token, userId, role, fullName) => set({ token, userId, role, fullName }),
      clearAuth: () => set({ token: null, userId: null, role: null, fullName: null }),
    }),
    { name: 'socblitz-auth' },
  ),
)

// ─── API client (Axios) ───────────────────────────────────────────────────────
import axios from 'axios'

const BASE_URL = ''

export const apiClient = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT to every request
apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) config.headers['Authorization'] = `Bearer ${token}`
  return config
})

// Auto-logout on 401
apiClient.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      useAuthStore.getState().clearAuth()
      window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)

// ─── API helper functions ─────────────────────────────────────────────────────
export const api = {
  // Auth
  login:       (email: string, password: string) =>
    apiClient.post('/auth/login', new URLSearchParams({ username: email, password }),
                  { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }),
  me:          () => apiClient.get('/auth/me'),
  listUsers:   () => apiClient.get('/auth/users'),
  createUser:  (data: any) => apiClient.post('/auth/users', data),

  // Dashboard / health
  health:      () => apiClient.get('/health/detailed'),

  // Alerts
  listAlerts:  (params?: any) => apiClient.get('/alerts', { params }),
  alertStats:  () => apiClient.get('/alerts/stats'),
  getAlert:    (id: string) => apiClient.get(`/alerts/${id}`),
  updateAlert: (id: string, data: any) => apiClient.patch(`/alerts/${id}`, data),
  ingestAlert: (data: any) => apiClient.post('/alerts', data),

  // Events (raw Wazuh alert stream, every level)
  listEvents:  (params?: any) => apiClient.get('/events', { params }),
  getEvent:    (id: string) => apiClient.get(`/events/${id}`),

  // AI dashboard agent
  floodingInsights:  (hours = 24) => apiClient.get('/ai/insights/flooding', { params: { hours } }),
  generateDashboard: (prompt: string, hours = 24) => apiClient.post('/ai/dashboard/generate', { prompt, hours }),
  listDashboards:    () => apiClient.get('/ai/dashboards'),
  createDashboard:   (name: string) => apiClient.post('/ai/dashboards', { name }),
  getDashboard:      (id: string, hours = 24) => apiClient.get(`/ai/dashboards/${id}`, { params: { hours } }),
  saveDashboard:     (id: string, name: string, widgets: any[]) => apiClient.put(`/ai/dashboards/${id}`, { name, widgets }),
  deleteDashboard:   (id: string) => apiClient.delete(`/ai/dashboards/${id}`),

  // Cases
  listCases:   (params?: any) => apiClient.get('/cases', { params }),
  getCase:     (id: string) => apiClient.get(`/cases/${id}`),
  createCase:  (data: any) => apiClient.post('/cases', data),
  updateCase:  (id: string, data: any) => apiClient.patch(`/cases/${id}`, data),
  addComment:  (caseId: string, content: string, isInternal = true) =>
    apiClient.post(`/cases/${caseId}/comments`, { content, is_internal: isInternal }),
  getComments: (caseId: string) => apiClient.get(`/cases/${caseId}/comments`),
  addObservable: (caseId: string, data: any) =>
    apiClient.post(`/cases/${caseId}/observables`, data),
  getObservables: (caseId: string) => apiClient.get(`/cases/${caseId}/observables`),
  deleteObservable: (caseId: string, obsId: string) =>
    apiClient.delete(`/cases/${caseId}/observables/${obsId}`),
  getCaseTimeline:   (caseId: string) => apiClient.get(`/cases/${caseId}/timeline`),
  addTimelineEvent:  (caseId: string, description: string, mitreTechniques: string[] = []) =>
    apiClient.post(`/cases/${caseId}/timeline`, { description, event_type: 'manual', mitre_techniques: mitreTechniques }),
  listCaseAlerts:    (caseId: string) => apiClient.get('/alerts', { params: { case_id: caseId, limit: 200 } }),
  listCaseTasks:     (caseId: string) => apiClient.get(`/cases/${caseId}/tasks`),
  createCaseTask:    (caseId: string, data: any) => apiClient.post(`/cases/${caseId}/tasks`, data),
  updateCaseTask:    (caseId: string, taskId: string, data: any) =>
    apiClient.patch(`/cases/${caseId}/tasks/${taskId}`, data),
  deleteCaseTask:    (caseId: string, taskId: string) =>
    apiClient.delete(`/cases/${caseId}/tasks/${taskId}`),

  // Case assets (DFIR-IRIS style)
  listCaseAssets:    (caseId: string) => apiClient.get(`/cases/${caseId}/assets`),
  createCaseAsset:   (caseId: string, data: any) => apiClient.post(`/cases/${caseId}/assets`, data),
  updateCaseAsset:   (caseId: string, assetId: string, data: any) =>
    apiClient.patch(`/cases/${caseId}/assets/${assetId}`, data),
  deleteCaseAsset:   (caseId: string, assetId: string) =>
    apiClient.delete(`/cases/${caseId}/assets/${assetId}`),

  // Case evidence
  listCaseEvidence:  (caseId: string) => apiClient.get(`/cases/${caseId}/evidence`),
  createCaseEvidence:(caseId: string, data: any) => apiClient.post(`/cases/${caseId}/evidence`, data),
  deleteCaseEvidence:(caseId: string, evidenceId: string) =>
    apiClient.delete(`/cases/${caseId}/evidence/${evidenceId}`),

  // Case notes (structured, IRIS-style)
  listCaseNotes:     (caseId: string) => apiClient.get(`/cases/${caseId}/notes`),
  createCaseNote:    (caseId: string, data: any) => apiClient.post(`/cases/${caseId}/notes`, data),
  updateCaseNote:    (caseId: string, noteId: string, data: any) =>
    apiClient.patch(`/cases/${caseId}/notes/${noteId}`, data),
  deleteCaseNote:    (caseId: string, noteId: string) =>
    apiClient.delete(`/cases/${caseId}/notes/${noteId}`),

  // MITRE ATT&CK reference
  listMitreTechniques: () => apiClient.get('/mitre/techniques'),

  // Case report
  downloadCaseReport: async (caseId: string, caseNumber: number | string) => {
    const res = await apiClient.get(`/cases/${caseId}/report`, { responseType: 'blob' })
    const url = window.URL.createObjectURL(new Blob([res.data]))
    const a = document.createElement('a')
    a.href = url
    a.download = `case-${caseNumber}-report.html`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.URL.revokeObjectURL(url)
  },

  // Agents
  listAgents:  (params?: any) => apiClient.get('/agents', { params }),
  syncAgents:  () => apiClient.post('/agents/sync'),
  agentVulns:  (id: string) => apiClient.get(`/agents/${id}/vulnerabilities`),

  // Connectors
  listConnectors:   () => apiClient.get('/connectors'),
  updateConnector:  (id: string, data: any) => apiClient.patch(`/connectors/${id}`, data),
  verifyConnector:  (id: string) => apiClient.post(`/connectors/${id}/verify`),

  // Threat Intel
  lookupIoc:    (value: string, type: string) => apiClient.post('/threat-intel/lookup', { value, type }),
  mispEvents:   () => apiClient.get('/threat-intel/misp/events'),

  // Tenants
  listTenants:  () => apiClient.get('/tenants'),
  createTenant: (data: any) => apiClient.post('/tenants', data),

  // SOAR
  listWorkflows:    () => apiClient.get('/soar/workflows'),
  getWorkflow:      (id: string) => apiClient.get(`/soar/workflows/${id}`),
  createWorkflow:   (data: any) => apiClient.post('/soar/workflows', data),
  updateWorkflow:   (id: string, data: any) => apiClient.patch(`/soar/workflows/${id}`, data),
  deleteWorkflow:   (id: string) => apiClient.delete(`/soar/workflows/${id}`),
  runWorkflow:      (id: string, data?: any) => apiClient.post(`/soar/workflows/${id}/run`, data || {}),
  listWorkflowRuns: (id: string) => apiClient.get(`/soar/workflows/${id}/runs`),
  listNodeTypes:    () => apiClient.get('/soar/node-types'),
}
