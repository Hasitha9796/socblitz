import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { useAuthStore } from './stores/auth'
import DashboardLayout from './layouts/DashboardLayout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Events from './pages/Events'
import EventDetail from './pages/EventDetail'
import CustomDashboard from './pages/CustomDashboard'
import Cases from './pages/Cases'
import CaseDetail from './pages/CaseDetail'
import Agents from './pages/Agents'
import Connectors from './pages/Connectors'
import ThreatIntel from './pages/ThreatIntel'
import Forensics from './pages/Forensics'
import SOAR from './pages/SOAR'
import WorkflowBuilder from './pages/WorkflowBuilder'
import Settings from './pages/Settings'
import AccountSecurity from './pages/AccountSecurity'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 2,
      refetchOnWindowFocus: false,
    },
  },
})

function AuthGuard({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token)
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <AuthGuard>
                <DashboardLayout />
              </AuthGuard>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard"    element={<Dashboard />} />
            <Route path="alerts"       element={<Alerts />} />
            <Route path="alerts/:id"   element={<AlertDetail />} />
            <Route path="events"       element={<Events />} />
            <Route path="events/:id"   element={<EventDetail />} />
            <Route path="custom-dashboard" element={<CustomDashboard />} />
            <Route path="cases"        element={<Cases />} />
            <Route path="cases/:id"    element={<CaseDetail />} />
            <Route path="agents"       element={<Agents />} />
            <Route path="threat-intel" element={<ThreatIntel />} />
            <Route path="forensics"    element={<Forensics />} />
            <Route path="soar"         element={<SOAR />} />
            <Route path="soar/new"     element={<WorkflowBuilder />} />
            <Route path="soar/:id/edit" element={<WorkflowBuilder />} />
            <Route path="connectors"   element={<Connectors />} />
            <Route path="settings"     element={<Settings />} />
            <Route path="account"      element={<AccountSecurity />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: '#1a2035',
            color: '#e2e8f0',
            border: '1px solid rgba(255,255,255,0.08)',
            fontSize: '13px',
          },
          success: { iconTheme: { primary: '#22d3ee', secondary: '#1a2035' } },
          error:   { iconTheme: { primary: '#f43f5e', secondary: '#1a2035' } },
        }}
      />
    </QueryClientProvider>
  )
}
