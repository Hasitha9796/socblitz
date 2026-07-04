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

  // Cases
  listCases:   (params?: any) => apiClient.get('/cases', { params }),
  getCase:     (id: string) => apiClient.get(`/cases/${id}`),
  createCase:  (data: any) => apiClient.post('/cases', data),
  updateCase:  (id: string, data: any) => apiClient.patch(`/cases/${id}`, data),
  addComment:  (caseId: string, content: string) =>
    apiClient.post(`/cases/${caseId}/comments`, { content }),
  getComments: (caseId: string) => apiClient.get(`/cases/${caseId}/comments`),
  addObservable: (caseId: string, data: any) =>
    apiClient.post(`/cases/${caseId}/observables`, data),
  getObservables: (caseId: string) => apiClient.get(`/cases/${caseId}/observables`),

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
  listWorkflows: () => apiClient.get('/soar/workflows'),
  runWorkflow:   (id: string, data?: any) => apiClient.post(`/soar/workflows/${id}/run`, data || {}),
}
