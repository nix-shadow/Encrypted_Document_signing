import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'

const api = async (path, options = {}) => {
  // Get CSRF token if needed for state-changing operations
  let csrfToken = null
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method)) {
    try {
      const tokenRes = await fetch('/api/auth/csrf-token', { credentials: 'include' })
      const tokenData = await tokenRes.json()
      csrfToken = tokenData.csrf_token
    } catch (e) {
      console.warn('CSRF token fetch failed:', e)
    }
  }

  // Build headers - don't set Content-Type for FormData
  const headers = {
    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
    ...(options.headers || {}),
  }
  
  // Only set Content-Type if body is NOT FormData
  if (options.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json'
  }

  const res = await fetch(`/api${path}`, {
    credentials: 'include',
    ...options,
    headers,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || res.statusText)
  }
  if (res.headers.get('content-type')?.includes('application/json')) {
    return res.json()
  }
  return res.text()
}

// Icons as SVG components
const LockIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
)

const CheckIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
)

const XIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
    <line x1="18" y1="6" x2="6" y2="18"/>
    <line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
)

const FileIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
    <polyline points="13 2 13 9 20 9"/>
  </svg>
)

const ShareIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="18" cy="5" r="3"/>
    <circle cx="6" cy="12" r="3"/>
    <circle cx="18" cy="19" r="3"/>
    <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
    <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
  </svg>
)

const UploadIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
    <polyline points="17 8 12 3 7 8"/>
    <line x1="12" y1="3" x2="12" y2="15"/>
  </svg>
)
const DownloadIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
    <polyline points="7 10 12 15 17 10"/>
    <line x1="12" y1="15" x2="12" y2="3"/>
  </svg>
)
const Badge = ({ ok, label, icon }) => (
  <span
    style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '4px',
      padding: '6px 12px',
      borderRadius: '16px',
      background: ok ? '#00875a' : '#de350b',
      color: 'white',
      fontSize: '13px',
      fontWeight: '600',
      marginLeft: '8px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
      animation: 'fadeIn 0.3s ease-in',
    }}
  >
    {icon}
    {label}
  </span>
)

const Spinner = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" style={{ animation: 'spin 1s linear infinite' }}>
    <circle cx="12" cy="12" r="10" stroke="#0066cc" strokeWidth="3" fill="none" strokeDasharray="60" strokeDashoffset="15" strokeLinecap="round"/>
  </svg>
)

function App() {
  const [user, setUser] = useState(null)
  const [docs, setDocs] = useState([])
  const [selected, setSelected] = useState(null)
  const [message, setMessage] = useState({ text: '', type: 'info' })
  const [loading, setLoading] = useState(false)
  const [showRegister, setShowRegister] = useState(false)
  const [showAdminPanel, setShowAdminPanel] = useState(false)
  const [showProfile, setShowProfile] = useState(false)
  const [profileTab, setProfileTab] = useState('profile')
  const [pendingUsers, setPendingUsers] = useState([])
  const [allUsers, setAllUsers] = useState([])
  const [pendingLogins, setPendingLogins] = useState([])
  const [pendingDevices, setPendingDevices] = useState([])
  const [allDevices, setAllDevices] = useState([])
  const [auditLogs, setAuditLogs] = useState([])
  const [trustedDevices, setTrustedDevices] = useState([])
  const [mfaEnabled, setMfaEnabled] = useState(false)
  const [mfaSetupData, setMfaSetupData] = useState(null)
  const [viewingSessions, setViewingSessions] = useState([])
  const [allViewingSessions, setAllViewingSessions] = useState([])

  const showMessage = (text, type = 'info') => {
    setMessage({ text, type })
    setTimeout(() => setMessage({ text: '', type: 'info' }), 5000)
  }

  const loadMe = async () => {
    try {
      const me = await api('/users/me')
      setUser(me)
    } catch (e) {
      setUser(null)
    }
  }

  const loadDocs = async () => {
    try {
      const data = await api('/documents')
      setDocs(data)
    } catch (e) {
      showMessage(e.message, 'error')
    }
  }

  // Generate device fingerprint from browser characteristics
  const generateFingerprint = () => {
    const nav = navigator
    const screen = window.screen
    const components = [
      nav.userAgent,
      nav.language,
      screen.colorDepth,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      !!window.sessionStorage,
      !!window.localStorage,
    ]
    return btoa(components.join('|')).substring(0, 32)
  }

  useEffect(() => {
    loadMe()
    loadDocs()
  }, [])

  // Auto-refresh viewing sessions every 10 seconds for selected document
  useEffect(() => {
    if (!selected?.id || !user) return
    
    const interval = setInterval(() => {
      loadViewingSessions(selected.id)
    }, 10000) // 10 seconds
    
    return () => clearInterval(interval)
  }, [selected?.id, user])

  // Auto-refresh admin viewing sessions every 15 seconds
  useEffect(() => {
    if (!showAdminPanel || !user || user.role !== 'admin') return
    
    const interval = setInterval(() => {
      loadAllViewingSessions()
    }, 15000) // 15 seconds
    
    return () => clearInterval(interval)
  }, [showAdminPanel, user])

  const handleRegister = async (e) => {
    e.preventDefault()
    const email = e.target.email.value
    const password = e.target.password.value
    setLoading(true)
    try {
      await api('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ 
          email, 
          password,
          device_fingerprint: generateFingerprint()
        }),
      })
      showMessage('✓ Registered successfully! Please login.', 'success')
      setShowRegister(false)
      e.target.reset()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    const email = e.target.email.value
    const password = e.target.password.value
    setLoading(true)
    try {
      await api('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ 
          email, 
          password,
          device_fingerprint: generateFingerprint()
        }),
      })
      await loadMe()
      await loadDocs()
      showMessage('✓ Logged in successfully!', 'success')
      e.target.reset()
    } catch (err) {
      showMessage(err.message, 'error')
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = async () => {
    await api('/auth/logout', { method: 'POST' })
    setUser(null)
    setDocs([])
    setSelected(null)
    showMessage('✓ Logged out successfully', 'info')
  }

  const handleUpload = async (e) => {
    e.preventDefault()
    const file = e.target.file.files[0]
    if (!file) return
    const pdfPassword = e.target.pdfPassword?.value || null
    
    const data = new FormData()
    data.append('file', file)
    if (pdfPassword) {
      data.append('pdf_password', pdfPassword)
    }
    
    setLoading(true)
    try {
      await api('/documents/upload', { method: 'POST', body: data })
    const msg = pdfPassword 
        ? '✓ Document encrypted, signed, and password-protected!' 
        : '✓ Document encrypted and signed successfully!'
      showMessage(msg, 'success')
      e.target.reset()
      loadDocs()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const openDoc = async (id, pdfPassword = null) => {
    setLoading(true)
    try {
      let url = `/documents/${id}`
      if (pdfPassword) {
        url += `?pdf_password=${encodeURIComponent(pdfPassword)}`
      }
      const doc = await api(url)
      setSelected(doc)
      const status = doc.verified ? '✓ Verified' : '⚠ Unverified'
      showMessage(`${status} - Document decrypted successfully`, doc.verified ? 'success' : 'warning')
      // Load viewing sessions for owner/admin
      loadViewingSessions(id)
    } catch (err) {
      // Check if error is about file password
      if (err.message.includes('password required')) {
        const password = prompt('This file requires a password to open:')
        if (password) {
          openDoc(id, password)  // Retry with password
        } else {
          showMessage('File password required to open this document', 'error')
        }
      } else {
        showMessage(err.message, 'error')
      }
    } finally {
      setLoading(false)
    }
  }

  const loadViewingSessions = async (docId) => {
    if (!user) return
    try {
      const sessions = await api(`/documents/${docId}/viewing-sessions`)
      setViewingSessions(sessions)
    } catch (err) {
      // User might not have permission
      setViewingSessions([])
    }
  }

  const approveViewer = async (docId, sessionId, approve) => {
    setLoading(true)
    try {
      await api(`/documents/${docId}/approve-viewer/${sessionId}`, {
        method: 'POST',
        body: JSON.stringify({ approve })
      })
      showMessage(approve ? '✓ Viewer approved' : '✗ Viewer rejected', 'success')
      loadViewingSessions(docId)
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const endSession = async (docId, sessionId) => {
    setLoading(true)
    try {
      await api(`/documents/${docId}/end-session/${sessionId}`, { method: 'POST' })
      showMessage('✓ Viewing session ended', 'success')
      loadViewingSessions(docId)
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const shareDoc = async (e) => {
    e.preventDefault()
    if (!selected) return
    const recipient_email = e.target.email.value
    setLoading(true)
    try {
      await api(`/documents/${selected.id}/share`, {
        method: 'POST',
        body: JSON.stringify({ recipient_email }),
      })
      showMessage(`✓ Document shared with ${recipient_email}`, 'success')
      e.target.reset()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const downloadDoc = () => {
    if (!selected) return
    
    // Decode base64 content
    const binaryString = atob(selected.content_b64)
    const bytes = new Uint8Array(binaryString.length)
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i)
    }
    
    // Determine filename - add .zip if password protected
    let downloadFilename = selected.filename
    if (selected.has_pdf_password) {
      // File is wrapped in password-protected ZIP
      downloadFilename = selected.filename + '.zip'
    }
    
    // Create blob and download
    const blob = new Blob([bytes], { type: selected.content_type })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = downloadFilename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    
    const msg = selected.has_pdf_password 
      ? `✓ Downloaded ${downloadFilename} (password-protected)` 
      : `✓ Downloaded ${selected.filename}`
    showMessage(msg, 'success')
  }

  const deleteDoc = async (id) => {
    if (!confirm('Are you sure you want to delete this document?')) return
    setLoading(true)
    try {
      await api(`/documents/${id}`, { method: 'DELETE' })
      showMessage('✓ Document deleted', 'success')
      if (selected?.id === id) setSelected(null)
      loadDocs()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  // Admin functions
  const loadAdminData = async () => {
    if (!user?.role || user.role !== 'admin') return
    try {
      const [users, pending, logins, devices, allDevs] = await Promise.all([
        api('/auth/admin/users'),
        api('/auth/admin/pending-users'),
        api('/auth/admin/pending-logins'),
        api('/auth/admin/pending-devices'),
        api('/auth/admin/all-devices'),
      ])
      setAllUsers(users)
      setPendingUsers(pending)
      setPendingLogins(logins)
      setPendingDevices(devices)
      setAllDevices(allDevs)
      // Load all viewing sessions
      loadAllViewingSessions()
    } catch (err) {
      showMessage('Error loading admin data: ' + err.message, 'error')
    }
  }

  const loadAllViewingSessions = async () => {
    if (!user?.role || user.role !== 'admin') return
    try {
      // Get all documents first
      const allDocs = await api('/documents')
      const allSessions = []
      
      // Fetch viewing sessions for each document
      for (const doc of allDocs) {
        try {
          const sessions = await api(`/documents/${doc.id}/viewing-sessions`)
          sessions.forEach(s => {
            allSessions.push({ ...s, document_name: doc.filename, document_id: doc.id })
          })
        } catch (e) {
          // Skip if no access
        }
      }
      setAllViewingSessions(allSessions)
    } catch (err) {
      console.error('Failed to load viewing sessions:', err)
    }
  }

  const approveUser = async (userId) => {
    setLoading(true)
    try {
      await api(`/auth/admin/approve-user/${userId}`, { method: 'POST' })
      showMessage('✓ User approved successfully', 'success')
      loadAdminData()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const rejectUser = async (userId) => {
    if (!confirm('Are you sure you want to reject this user?')) return
    setLoading(true)
    try {
      await api(`/auth/admin/reject-user/${userId}`, { method: 'POST' })
      showMessage('✓ User rejected', 'success')
      loadAdminData()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const approveLogin = async (pendingId, approve) => {
    setLoading(true)
    try {
      await api(`/auth/admin/approve-login/${pendingId}`, {
        method: 'POST',
        body: JSON.stringify({ approve }),
      })
      showMessage(`✓ Login ${approve ? 'approved' : 'rejected'}`, 'success')
      loadAdminData()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const approveDevice = async (pendingId, approve) => {
    setLoading(true)
    try {
      await api(`/auth/admin/approve-device/${pendingId}`, {
        method: 'POST',
        body: JSON.stringify({ approve }),
      })
      showMessage(`✓ Device ${approve ? 'approved' : 'rejected'}`, 'success')
      loadAdminData()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const trustDevice = async (deviceId) => {
    setLoading(true)
    try {
      await api(`/auth/admin/trust-device/${deviceId}`, { method: 'POST' })
      showMessage('✓ Device trusted successfully', 'success')
      loadAdminData()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const deleteUser = async (userId) => {
    if (!confirm('Are you sure you want to delete this user? This cannot be undone.')) return
    setLoading(true)
    try {
      await api(`/auth/admin/delete-user/${userId}`, { method: 'DELETE' })
      showMessage('✓ User deleted', 'success')
      loadAdminData()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  // Profile functions
  const loadProfileData = async () => {
    try {
      const [logs, devices, mfaStatus] = await Promise.all([
        api('/users/audit-logs'),
        api('/users/trusted-devices'),
        api('/users/mfa/status')
      ])
      setAuditLogs(logs)
      setTrustedDevices(devices)
      setMfaEnabled(mfaStatus.enabled)
    } catch (err) {
      showMessage('Error loading profile data: ' + err.message, 'error')
    }
  }

  const setupMFA = async () => {
    setLoading(true)
    try {
      const data = await api('/users/mfa/setup', { method: 'POST' })
      setMfaSetupData(data)
      showMessage('✓ MFA setup initiated', 'success')
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const enableMFA = async (token) => {
    setLoading(true)
    try {
      await api('/users/mfa/enable', { method: 'POST', body: JSON.stringify({ token }) })
      setMfaEnabled(true)
      setMfaSetupData(null)
      showMessage('✓ MFA enabled successfully', 'success')
      loadProfileData()
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const disableMFA = async () => {
    if (!confirm('Are you sure you want to disable MFA?')) return
    setLoading(true)
    try {
      await api('/users/mfa/disable', { method: 'POST' })
      setMfaEnabled(false)
      showMessage('✓ MFA disabled', 'success')
    } catch (err) {
      showMessage(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  // Load admin data when user changes
  useEffect(() => {
    if (user?.role === 'admin' && showAdminPanel) {
      loadAdminData()
    }
  }, [user, showAdminPanel])

  useEffect(() => {
    if (user && showProfile) {
      loadProfileData()
    }
  }, [user, showProfile])

  const messageStyles = {
    info: { background: 'linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%)', color: '#1e40af', border: '1px solid #93c5fd' },
    success: { background: 'linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%)', color: '#065f46', border: '1px solid #6ee7b7' },
    error: { background: 'linear-gradient(135deg, #fee2e2 0%, #fecaca 100%)', color: '#991b1b', border: '1px solid #fca5a5' },
    warning: { background: 'linear-gradient(135deg, #fef3c7 0%, #fde68a 100%)', color: '#92400e', border: '1px solid #fcd34d' },
  }

  return (
    <div style={{ minHeight: '100vh', background: '#f7fafc' }}>
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes slideIn {
          from { opacity: 0; transform: translateX(-20px); }
          to { opacity: 1; transform: translateX(0); }
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
        input, textarea, button {
          padding: 12px 16px;
          border-radius: 8px;
          border: 1px solid #e2e8f0;
          font-size: 14px;
          font-family: inherit;
          transition: all 0.2s;
        }
        input:focus, textarea:focus {
          outline: none;
          border-color: #6366f1;
          box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }
        button {
          background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
          color: white;
          border: none;
          cursor: pointer;
          font-weight: 600;
          box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }
        button:hover:not(:disabled) {
          transform: translateY(-2px);
          box-shadow: 0 6px 16px rgba(99, 102, 241, 0.4);
        }
        button:active:not(:disabled) {
          transform: translateY(0);
        }
        button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }
        button.secondary {
          background: white;
          color: #0066cc;
          border: 2px solid #cbd5e0;
          box-shadow: none;
        }
        button.danger {
          background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
          box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }
        .card {
          background: white;
          border-radius: 16px;
          padding: 24px;
          box-shadow: 0 10px 40px rgba(0,0,0,0.1);
          animation: fadeIn 0.5s ease-out;
        }
        .doc-item {
          padding: 12px;
          border-radius: 8px;
          transition: all 0.2s;
          cursor: pointer;
          animation: slideIn 0.3s ease-out;
        }
        .doc-item:hover {
          background: #f8fafc;
          transform: translateX(4px);
        }
      `}</style>

      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '24px' }}>
        {/* Header */}
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', color: '#1e293b' }}>
            <LockIcon />
            <div>
              <h1 style={{ margin: 0, fontSize: '32px', fontWeight: '700', color: '#6366f1' }}>SecureSign</h1>
              <p style={{ margin: '4px 0 0 0', opacity: 0.8, fontSize: '14px', color: '#64748b' }}>
                End-to-end encrypted document signing with AES-256-GCM + RSA-2048
              </p>
            </div>
          </div>
          {user && (
            <div className="card" style={{ padding: '12px 20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div>
                <div style={{ fontWeight: '600', color: '#1e293b', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {user.email}
                  {user.role === 'admin' && (
                    <span style={{ 
                      background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)', 
                      color: 'white', 
                      padding: '2px 8px', 
                      borderRadius: '6px', 
                      fontSize: '11px', 
                      fontWeight: '700',
                      boxShadow: '0 2px 8px rgba(245, 158, 11, 0.3)'
                    }}>
                      ADMIN
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '12px', color: '#64748b' }}>RSA Keys Generated</div>
              </div>
              {user.role === 'admin' && (
                <button 
                  onClick={() => { setShowAdminPanel(!showAdminPanel); setShowProfile(false); }} 
                  className="secondary"
                  style={{ padding: '8px 16px' }}
                >
                  {showAdminPanel ? '📄 Documents' : '⚙️ Admin Panel'}
                </button>
              )}
              <button 
                onClick={() => { setShowProfile(!showProfile); setShowAdminPanel(false); }} 
                className="secondary"
                style={{ padding: '8px 16px' }}
              >
                {showProfile ? '📄 Documents' : '👤 Profile'}
              </button>
              <button onClick={handleLogout} style={{ padding: '8px 16px' }}>Logout</button>
            </div>
          )}
        </header>

        {/* Message Banner */}
        {message.text && (
          <div style={{
            ...messageStyles[message.type],
            padding: '16px 20px',
            borderRadius: '12px',
            marginBottom: '24px',
            fontWeight: '500',
            animation: 'fadeIn 0.3s ease-in',
          }}>
            {message.text}
          </div>
        )}

        {/* Auth Forms */}
        {!user && (
          <div className="card" style={{ maxWidth: '500px', margin: '0 auto' }}>
            <div style={{ textAlign: 'center', marginBottom: '24px' }}>
              <h2 style={{ margin: '0 0 8px 0', color: '#1e293b' }}>
                {showRegister ? 'Create Account' : 'Welcome Back'}
              </h2>
              <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>
                {showRegister 
                  ? 'Register to start encrypting your documents' 
                  : 'Login to access your encrypted documents'}
              </p>
            </div>

            {showRegister ? (
              <form onSubmit={handleRegister}>
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', marginBottom: '6px', fontWeight: '600', color: '#475569', fontSize: '14px' }}>
                    Email
                  </label>
                  <input 
                    name="email" 
                    placeholder="you@example.com" 
                    type="email" 
                    required 
                    style={{ width: '100%' }} 
                  />
                </div>
                <div style={{ marginBottom: '20px' }}>
                  <label style={{ display: 'block', marginBottom: '6px', fontWeight: '600', color: '#475569', fontSize: '14px' }}>
                    Password
                  </label>
                  <input 
                    name="password" 
                    placeholder="Min 8 chars, 1 uppercase, 1 number" 
                    type="password" 
                    required 
                    style={{ width: '100%' }} 
                  />
                  <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>
                    Your RSA-2048 keys will be generated automatically
                  </div>
                </div>
                <button disabled={loading} type="submit" style={{ width: '100%', marginBottom: '12px' }}>
                  {loading ? <Spinner /> : 'Create Account'}
                </button>
                <button 
                  type="button" 
                  className="secondary" 
                  onClick={() => setShowRegister(false)}
                  style={{ width: '100%' }}
                >
                  Already have an account? Login
                </button>
              </form>
            ) : (
              <form onSubmit={handleLogin}>
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', marginBottom: '6px', fontWeight: '600', color: '#475569', fontSize: '14px' }}>
                    Email
                  </label>
                  <input 
                    name="email" 
                    placeholder="you@example.com" 
                    type="email" 
                    required 
                    style={{ width: '100%' }} 
                  />
                </div>
                <div style={{ marginBottom: '20px' }}>
                  <label style={{ display: 'block', marginBottom: '6px', fontWeight: '600', color: '#475569', fontSize: '14px' }}>
                    Password
                  </label>
                  <input 
                    name="password" 
                    placeholder="Enter your password" 
                    type="password" 
                    required 
                    style={{ width: '100%' }} 
                  />
                </div>
                <button disabled={loading} type="submit" style={{ width: '100%', marginBottom: '12px' }}>
                  {loading ? <Spinner /> : 'Login'}
                </button>
                <button 
                  type="button" 
                  className="secondary" 
                  onClick={() => setShowRegister(true)}
                  style={{ width: '100%' }}
                >
                  Don't have an account? Register
                </button>
              </form>
            )}
          </div>
        )}

        {/* Main Content */}
        {user && !showAdminPanel && !showProfile && (
          <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: '24px' }}>
            {/* Sidebar */}
            <div>
              {/* Upload Card */}
              <div className="card" style={{ marginBottom: '24px' }}>
                <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px', color: '#1e293b' }}>
                  <UploadIcon />
                  Upload Document
                </h3>
                <form onSubmit={handleUpload}>
                  <div style={{ 
                    border: '2px dashed #cbd5e1', 
                    borderRadius: '12px', 
                    padding: '24px', 
                    textAlign: 'center',
                    marginBottom: '12px',
                    background: '#f8fafc',
                    transition: 'all 0.2s',
                  }}
                  onDragOver={(e) => { e.preventDefault(); e.currentTarget.style.borderColor = '#0066cc'; e.currentTarget.style.background = '#f0f7ff'; }}
                  onDragLeave={(e) => { e.currentTarget.style.borderColor = '#cbd5e1'; e.currentTarget.style.background = '#f8fafc'; }}
                  onDrop={(e) => { e.preventDefault(); e.currentTarget.style.borderColor = '#cbd5e1'; e.currentTarget.style.background = '#f8fafc'; }}>
                    <input 
                      name="file" 
                      type="file" 
                      required 
                      style={{ 
                        width: '100%', 
                        padding: '8px',
                        border: 'none',
                        background: 'transparent',
                        cursor: 'pointer'
                      }} 
                    />
                    <div style={{ fontSize: '12px', color: '#64748b', marginTop: '8px' }}>
                      Max 50MB • PDF, DOCX, TXT, JPG, PNG, CSV
                    </div>
                  </div>
                  <div style={{ marginBottom: '12px' }}>
                    <label style={{ display: 'block', marginBottom: '6px', fontWeight: '600', color: '#475569', fontSize: '13px' }}>
                      File Password (Optional) 🔒
                    </label>
                    <input 
                      name="pdfPassword" 
                      type="password"
                      placeholder="Protect your downloaded file"
                      style={{ 
                        width: '100%', 
                        padding: '10px',
                        fontSize: '14px'
                      }} 
                    />
                    <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
                      Works for ALL file types (PDF, DOCX, TXT, Excel, etc.)
                    </div>
                  </div>
                  <button disabled={loading} type="submit" style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                    {loading ? <Spinner /> : (
                      <>
                        <LockIcon />
                        Encrypt & Sign
                      </>
                    )}
                  </button>
                </form>
              </div>

              {/* Documents List */}
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px', color: '#1e293b' }}>
                  <FileIcon />
                  Your Documents
                  <span style={{ 
                    marginLeft: 'auto', 
                    background: '#f1f5f9', 
                    padding: '4px 12px', 
                    borderRadius: '12px',
                    fontSize: '13px',
                    fontWeight: '600',
                    color: '#475569'
                  }}>
                    {docs.length}
                  </span>
                </h3>
                <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
                  {docs.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '32px 16px', color: '#94a3b8' }}>
                      <FileIcon />
                      <p style={{ margin: '8px 0 0 0' }}>No documents yet</p>
                      <p style={{ margin: '4px 0 0 0', fontSize: '13px' }}>Upload your first document</p>
                    </div>
                  ) : (
                    docs.map((d, idx) => (
                      <div
                        key={d.id}
                        className="doc-item"
                        onClick={() => openDoc(d.id)}
                        style={{ 
                          borderBottom: idx < docs.length - 1 ? '1px solid #f1f5f9' : 'none',
                          background: selected?.id === d.id ? '#eef2ff' : 'transparent',
                          animationDelay: `${idx * 0.05}s`
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                          <FileIcon />
                          <span style={{ fontWeight: '600', color: '#1e293b', flex: 1 }}>{d.filename}</span>
                          {d.has_pdf_password && (
                            <span style={{ fontSize: '11px', background: '#fef3c7', color: '#92400e', padding: '2px 8px', borderRadius: '8px', fontWeight: '600' }}>
                              🔒 ZIP
                            </span>
                          )}
                          {d.owner_id !== user.id && (
                            <span style={{ fontSize: '11px', background: '#dbeafe', color: '#1e40af', padding: '2px 8px', borderRadius: '8px', fontWeight: '600' }}>
                              SHARED
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '12px', color: '#64748b', paddingLeft: '26px' }}>
                          {d.owner_id === user.id ? 'Owner' : 'Shared with you'}
                          {d.verified !== undefined && (
                            <Badge ok={d.verified} label={d.verified ? 'Verified' : 'Unverified'} icon={d.verified ? <CheckIcon /> : <XIcon />} />
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Main Viewer */}
            <div className="card" style={{ minHeight: '600px' }}>
              <h3 style={{ margin: '0 0 20px 0', color: '#1e293b' }}>Document Viewer</h3>
              {selected ? (
                <div>
                  {/* Document Header */}
                  <div style={{ 
                    background: 'linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%)', 
                    padding: '20px', 
                    borderRadius: '12px', 
                    marginBottom: '20px',
                    border: '1px solid #e2e8f0'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <FileIcon />
                        <strong style={{ fontSize: '18px', color: '#1e293b' }}>{selected.filename}</strong>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <Badge ok={selected.verified} label={selected.verified ? 'Verified' : 'Unverified'} icon={selected.verified ? <CheckIcon /> : <XIcon />} />
                        {selected.tampered && <Badge ok={false} label="Tampered" icon={<XIcon />} />}
                      </div>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '13px' }}>
                      <div>
                        <span style={{ color: '#64748b' }}>Type:</span>
                        <span style={{ marginLeft: '8px', color: '#1e293b', fontWeight: '600' }}>{selected.content_type}</span>
                      </div>
                      <div>
                        <span style={{ color: '#64748b' }}>Owner:</span>
                        <span style={{ marginLeft: '8px', color: '#1e293b', fontWeight: '600' }}>
                          {selected.owner_id === user.id ? 'You' : `User #${selected.owner_id}`}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Document Content */}
                  <div style={{ marginBottom: '20px' }}>
                    <label style={{ display: 'block', marginBottom: '8px', fontWeight: '600', color: '#475569', fontSize: '14px' }}>
                      Decrypted Content
                    </label>
                    <textarea
                      readOnly
                      value={atob(selected.content_b64)}
                      style={{ 
                        width: '100%', 
                        minHeight: '300px', 
                        fontFamily: 'ui-monospace, monospace',
                        fontSize: '13px',
                        background: '#f8fafc',
                        resize: 'vertical'
                      }}
                    />
                  </div>

                  {/* Action Buttons */}
                  <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap' }}>
                    <button 
                      onClick={downloadDoc}
                      style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        justifyContent: 'center', 
                        gap: '8px',
                        flex: '1',
                        minWidth: '180px'
                      }}
                    >
                      <DownloadIcon />
                      Download File
                    </button>
                    {selected.owner_id === user.id && (
                      <button 
                        onClick={() => deleteDoc(selected.id)} 
                        className="danger"
                        disabled={loading}
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                      >
                        {loading ? <Spinner /> : (
                          <>
                            <XIcon />
                            Delete Document
                          </>
                        )}
                      </button>
                    )}
                  </div>

                  {/* Viewing Sessions Section (Owner/Admin) */}
                  {(selected.owner_id === user.id || user.role === 'admin') && viewingSessions.length > 0 && (
                    <div style={{ 
                      background: 'linear-gradient(135deg, #fef3c7 0%, #fde68a 100%)', 
                      padding: '20px', 
                      borderRadius: '12px',
                      border: '1px solid #fcd34d',
                      marginBottom: '20px'
                    }}>
                      <h4 style={{ margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px', color: '#92400e' }}>
                        👁️ Currently Viewing Devices
                        <span style={{ 
                          marginLeft: 'auto', 
                          background: '#92400e', 
                          color: '#fef3c7',
                          padding: '4px 12px', 
                          borderRadius: '12px',
                          fontSize: '13px',
                          fontWeight: '600'
                        }}>
                          {viewingSessions.length}
                        </span>
                      </h4>
                      <div style={{ display: 'grid', gap: '12px' }}>
                        {viewingSessions.map(session => (
                          <div 
                            key={session.id}
                            style={{
                              background: 'white',
                              padding: '12px',
                              borderRadius: '8px',
                              border: '1px solid #fcd34d',
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center'
                            }}
                          >
                            <div style={{ flex: 1 }}>
                              <div style={{ fontWeight: '600', color: '#1e293b', fontSize: '14px' }}>
                                {session.user_email}
                              </div>
                              <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                                Device: {session.device_name || 'Unknown'} • IP: {session.ip_address}
                              </div>
                              <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                                Started: {new Date(session.started_at).toLocaleString()} • 
                                Active: {new Date(session.last_active_at).toLocaleString()}
                              </div>
                            </div>
                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                              <span style={{
                                background: session.status === 'approved' ? '#d1fae5' : 
                                           session.status === 'pending' ? '#fef3c7' : '#fee2e2',
                                color: session.status === 'approved' ? '#065f46' :
                                       session.status === 'pending' ? '#92400e' : '#991b1b',
                                padding: '4px 10px',
                                borderRadius: '8px',
                                fontSize: '11px',
                                fontWeight: '700',
                                textTransform: 'uppercase'
                              }}>
                                {session.status}
                              </span>
                              {session.status === 'pending' && (
                                <>
                                  <button 
                                    onClick={() => approveViewer(selected.id, session.id, true)}
                                    disabled={loading}
                                    style={{ padding: '6px 12px', fontSize: '12px' }}
                                  >
                                    ✓ Approve
                                  </button>
                                  <button 
                                    onClick={() => approveViewer(selected.id, session.id, false)}
                                    disabled={loading}
                                    className="danger"
                                    style={{ padding: '6px 12px', fontSize: '12px' }}
                                  >
                                    ✗ Reject
                                  </button>
                                </>
                              )}
                              {session.status === 'approved' && (
                                <button 
                                  onClick={() => endSession(selected.id, session.id)}
                                  disabled={loading}
                                  className="danger"
                                  style={{ padding: '6px 12px', fontSize: '12px' }}
                                >
                                  End Session
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Share Section */}
                  {selected.owner_id === user.id && (
                    <div style={{ 
                      background: 'linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%)', 
                      padding: '20px', 
                      borderRadius: '12px',
                      border: '1px solid #bfdbfe'
                    }}>
                      <h4 style={{ margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: '8px', color: '#1e40af' }}>
                        <ShareIcon />
                        Share Document
                      </h4>
                      <p style={{ margin: '0 0 12px 0', fontSize: '13px', color: '#1e40af' }}>
                        Re-encrypt the AES key with recipient's RSA public key
                      </p>
                      <form onSubmit={shareDoc} style={{ display: 'flex', gap: '12px' }}>
                        <input 
                          name="email" 
                          type="email" 
                          placeholder="recipient@example.com" 
                          required 
                          style={{ flex: 1 }}
                        />
                        <button disabled={loading} type="submit" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {loading ? <Spinner /> : (
                            <>
                              <ShareIcon />
                              Share
                            </>
                          )}
                        </button>
                      </form>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ 
                  display: 'flex', 
                  flexDirection: 'column', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  height: '500px',
                  color: '#94a3b8'
                }}>
                  <LockIcon />
                  <p style={{ margin: '16px 0 0 0', fontSize: '16px', fontWeight: '600' }}>No Document Selected</p>
                  <p style={{ margin: '8px 0 0 0', fontSize: '14px' }}>
                    Select a document from the list to decrypt and verify
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Admin Panel */}
        {user && user.role === 'admin' && showAdminPanel && (
          <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
            <div style={{ marginBottom: '24px' }}>
              <h2 style={{ margin: '0 0 8px 0', color: '#1e293b', fontSize: '28px', fontWeight: '700' }}>
                ⚙️ Admin Dashboard
              </h2>
              <p style={{ margin: 0, color: '#64748b' }}>
                Manage users, approve access requests, and monitor system activity
              </p>
            </div>

            <div style={{ display: 'grid', gap: '24px' }}>
              {/* Pending Users */}
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  👥 Pending User Approvals
                  {pendingUsers.length > 0 && (
                    <span style={{ background: '#ef4444', color: 'white', padding: '2px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: '600' }}>
                      {pendingUsers.length}
                    </span>
                  )}
                </h3>
                {pendingUsers.length === 0 ? (
                  <p style={{ color: '#94a3b8', margin: 0 }}>No pending user approvals</p>
                ) : (
                  <div style={{ display: 'grid', gap: '12px' }}>
                    {pendingUsers.map(u => (
                      <div key={u.id} style={{ 
                        padding: '16px', 
                        background: '#f8fafc', 
                        borderRadius: '12px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                      }}>
                        <div>
                          <div style={{ fontWeight: '600', color: '#1e293b' }}>{u.email}</div>
                          <div style={{ fontSize: '13px', color: '#64748b' }}>
                            Registered: {new Date(u.created_at).toLocaleString()}
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button 
                            onClick={() => approveUser(u.id)}
                            disabled={loading}
                            style={{ padding: '8px 16px', fontSize: '13px' }}
                          >
                            ✓ Approve
                          </button>
                          <button 
                            onClick={() => rejectUser(u.id)}
                            disabled={loading}
                            className="danger"
                            style={{ padding: '8px 16px', fontSize: '13px' }}
                          >
                            ✗ Reject
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Pending Logins */}
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  🔐 Pending Login Requests
                  {pendingLogins.length > 0 && (
                    <span style={{ background: '#f59e0b', color: 'white', padding: '2px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: '600' }}>
                      {pendingLogins.length}
                    </span>
                  )}
                </h3>
                {pendingLogins.length === 0 ? (
                  <p style={{ color: '#94a3b8', margin: 0 }}>No pending login requests</p>
                ) : (
                  <div style={{ display: 'grid', gap: '12px' }}>
                    {pendingLogins.map(login => (
                      <div key={login.id} style={{ 
                        padding: '16px', 
                        background: '#fef3c7', 
                        borderRadius: '12px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                      }}>
                        <div>
                          <div style={{ fontWeight: '600', color: '#1e293b' }}>{login.user_email}</div>
                          <div style={{ fontSize: '13px', color: '#64748b' }}>
                            Device: {login.device_name} • IP: {login.ip_address}
                          </div>
                          <div style={{ fontSize: '12px', color: '#64748b' }}>
                            {new Date(login.created_at).toLocaleString()}
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button 
                            onClick={() => approveLogin(login.id, true)}
                            disabled={loading}
                            style={{ padding: '8px 16px', fontSize: '13px' }}
                          >
                            ✓ Approve
                          </button>
                          <button 
                            onClick={() => approveLogin(login.id, false)}
                            disabled={loading}
                            className="danger"
                            style={{ padding: '8px 16px', fontSize: '13px' }}
                          >
                            ✗ Reject
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Pending Devices */}
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  📱 Pending Device Authorizations
                  {pendingDevices.length > 0 && (
                    <span style={{ background: '#8b5cf6', color: 'white', padding: '2px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: '600' }}>
                      {pendingDevices.length}
                    </span>
                  )}
                </h3>
                {pendingDevices.length === 0 ? (
                  <p style={{ color: '#94a3b8', margin: 0 }}>No pending device authorizations</p>
                ) : (
                  <div style={{ display: 'grid', gap: '12px' }}>
                    {pendingDevices.map(device => (
                      <div key={device.id} style={{ 
                        padding: '16px', 
                        background: '#f3e8ff', 
                        borderRadius: '12px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                      }}>
                        <div>
                          <div style={{ fontWeight: '600', color: '#1e293b' }}>{device.user_email}</div>
                          <div style={{ fontSize: '13px', color: '#64748b' }}>
                            Device: {device.device_name} • IP: {device.ip_address}
                          </div>
                          <div style={{ fontSize: '12px', color: '#64748b' }}>
                            Fingerprint: {device.device_fingerprint}
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button 
                            onClick={() => approveDevice(device.id, true)}
                            disabled={loading}
                            style={{ padding: '8px 16px', fontSize: '13px' }}
                          >
                            ✓ Approve
                          </button>
                          <button 
                            onClick={() => approveDevice(device.id, false)}
                            disabled={loading}
                            className="danger"
                            style={{ padding: '8px 16px', fontSize: '13px' }}
                          >
                            ✗ Reject
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* All Users */}
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px' }}>
                  👤 All Users ({allUsers.length})
                </h3>
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Email</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Role</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Status</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Created</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allUsers.map(u => (
                        <tr key={u.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                          <td style={{ padding: '12px', color: '#1e293b' }}>{u.email}</td>
                          <td style={{ padding: '12px' }}>
                            <span style={{ 
                              background: u.role === 'admin' ? '#fef3c7' : '#dbeafe', 
                              color: u.role === 'admin' ? '#92400e' : '#1e40af',
                              padding: '4px 8px',
                              borderRadius: '6px',
                              fontSize: '12px',
                              fontWeight: '600'
                            }}>
                              {u.role.toUpperCase()}
                            </span>
                          </td>
                          <td style={{ padding: '12px' }}>
                            {u.is_approved ? (
                              <span style={{ color: '#059669', fontSize: '13px', fontWeight: '600' }}>✓ Approved</span>
                            ) : (
                              <span style={{ color: '#dc2626', fontSize: '13px', fontWeight: '600' }}>⚠ Pending</span>
                            )}
                          </td>
                          <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                            {new Date(u.created_at).toLocaleDateString()}
                          </td>
                          <td style={{ padding: '12px' }}>
                            {u.role !== 'admin' && (
                              <button 
                                onClick={() => deleteUser(u.id)}
                                disabled={loading}
                                className="danger"
                                style={{ padding: '6px 12px', fontSize: '12px' }}
                              >
                                Delete
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Active Viewing Sessions */}
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  👁️ Real-Time Document Viewers
                  {allViewingSessions.length > 0 && (
                    <span style={{ background: '#f59e0b', color: 'white', padding: '2px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: '600' }}>
                      {allViewingSessions.length} Active
                    </span>
                  )}
                </h3>
                {allViewingSessions.length === 0 ? (
                  <p style={{ color: '#94a3b8', margin: 0 }}>No active viewing sessions</p>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                          <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Document</th>
                          <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>User</th>
                          <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Device</th>
                          <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>IP Address</th>
                          <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Status</th>
                          <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Started</th>
                          <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Last Active</th>
                          <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {allViewingSessions.map(session => (
                          <tr key={`${session.document_id}-${session.id}`} style={{ borderBottom: '1px solid #f1f5f9' }}>
                            <td style={{ padding: '12px', color: '#1e293b', fontWeight: '600', fontSize: '13px' }}>
                              {session.document_name}
                            </td>
                            <td style={{ padding: '12px', color: '#1e293b' }}>{session.user_email}</td>
                            <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                              {session.device_name || 'Unknown'}
                            </td>
                            <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>{session.ip_address}</td>
                            <td style={{ padding: '12px' }}>
                              <span style={{
                                background: session.status === 'approved' ? '#d1fae5' : 
                                           session.status === 'pending' ? '#fef3c7' : '#fee2e2',
                                color: session.status === 'approved' ? '#065f46' :
                                       session.status === 'pending' ? '#92400e' : '#991b1b',
                                padding: '4px 10px',
                                borderRadius: '6px',
                                fontSize: '11px',
                                fontWeight: '700',
                                textTransform: 'uppercase'
                              }}>
                                {session.status}
                              </span>
                            </td>
                            <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                              {new Date(session.started_at).toLocaleString()}
                            </td>
                            <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                              {new Date(session.last_active_at).toLocaleString()}
                            </td>
                            <td style={{ padding: '12px' }}>
                              {session.status === 'pending' ? (
                                <div style={{ display: 'flex', gap: '4px' }}>
                                  <button 
                                    onClick={() => approveViewer(session.document_id, session.id, true)}
                                    disabled={loading}
                                    style={{ padding: '4px 8px', fontSize: '11px' }}
                                  >
                                    ✓
                                  </button>
                                  <button 
                                    onClick={() => approveViewer(session.document_id, session.id, false)}
                                    disabled={loading}
                                    className="danger"
                                    style={{ padding: '4px 8px', fontSize: '11px' }}
                                  >
                                    ✗
                                  </button>
                                </div>
                              ) : session.status === 'approved' ? (
                                <button 
                                  onClick={() => endSession(session.document_id, session.id)}
                                  disabled={loading}
                                  className="danger"
                                  style={{ padding: '4px 8px', fontSize: '11px' }}
                                >
                                  End
                                </button>
                              ) : '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* All Authenticated Devices */}
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px' }}>
                  🔐 All Authenticated Devices ({allDevices.length})
                </h3>
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>User</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Device</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>IP Address</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Status</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Last Used</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Created</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allDevices.map(device => (
                        <tr key={device.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                          <td style={{ padding: '12px', color: '#1e293b' }}>{device.user_email}</td>
                          <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                            {device.device_name}
                            <div style={{ fontSize: '11px', color: '#94a3b8' }}>
                              {device.device_fingerprint.substring(0, 16)}...
                            </div>
                          </td>
                          <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>{device.ip_address}</td>
                          <td style={{ padding: '12px' }}>
                            {device.is_trusted ? (
                              <span style={{ 
                                background: '#d1fae5', 
                                color: '#065f46',
                                padding: '4px 8px',
                                borderRadius: '6px',
                                fontSize: '12px',
                                fontWeight: '600'
                              }}>
                                ✓ Trusted
                              </span>
                            ) : (
                              <span style={{ 
                                background: '#fee2e2', 
                                color: '#991b1b',
                                padding: '4px 8px',
                                borderRadius: '6px',
                                fontSize: '12px',
                                fontWeight: '600'
                              }}>
                                ⚠ Untrusted
                              </span>
                            )}
                            {!device.is_active && (
                              <span style={{ 
                                marginLeft: '4px',
                                color: '#94a3b8',
                                fontSize: '11px'
                              }}>
                                (Inactive)
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                            {new Date(device.last_used_at).toLocaleString()}
                          </td>
                          <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                            {new Date(device.created_at).toLocaleDateString()}
                          </td>
                          <td style={{ padding: '12px' }}>
                            {!device.is_trusted && (
                              <button
                                onClick={() => trustDevice(device.id)}
                                style={{
                                  background: '#10b981',
                                  color: 'white',
                                  border: 'none',
                                  padding: '6px 12px',
                                  borderRadius: '6px',
                                  cursor: 'pointer',
                                  fontSize: '13px',
                                  fontWeight: '500'
                                }}
                              >
                                ✓ Trust Device
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Profile/Dashboard Panel */}
        {user && showProfile && (
          <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
            <div style={{ marginBottom: '24px' }}>
              <h2 style={{ margin: '0 0 8px 0', color: '#1e293b', fontSize: '28px', fontWeight: '700' }}>
                👤 User Dashboard
              </h2>
              <p style={{ margin: 0, color: '#64748b' }}>
                Manage your profile, security settings, and view activity logs
              </p>
            </div>

            {/* Tabs */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '24px', borderBottom: '2px solid #e2e8f0' }}>
              {['profile', 'mfa', 'audit', 'devices'].map(tab => (
                <button
                  key={tab}
                  onClick={() => setProfileTab(tab)}
                  style={{
                    background: profileTab === tab ? '#6366f1' : 'transparent',
                    color: profileTab === tab ? 'white' : '#64748b',
                    border: 'none',
                    padding: '12px 24px',
                    borderRadius: '8px 8px 0 0',
                    cursor: 'pointer',
                    fontWeight: '600',
                    fontSize: '14px',
                    transition: 'all 0.2s'
                  }}
                >
                  {tab === 'profile' && '📋 Profile'}
                  {tab === 'mfa' && '🔐 MFA Security'}
                  {tab === 'audit' && '📊 Audit Logs'}
                  {tab === 'devices' && '📱 Trusted Devices'}
                </button>
              ))}
            </div>

            {/* Profile Tab */}
            {profileTab === 'profile' && (
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px' }}>Profile Information</h3>
                <div style={{ display: 'grid', gap: '16px' }}>
                  <div>
                    <div style={{ fontWeight: '600', color: '#64748b', fontSize: '13px', marginBottom: '4px' }}>Email</div>
                    <div style={{ color: '#1e293b', fontSize: '16px' }}>{user.email}</div>
                  </div>
                  <div>
                    <div style={{ fontWeight: '600', color: '#64748b', fontSize: '13px', marginBottom: '4px' }}>Role</div>
                    <div style={{ color: '#1e293b', fontSize: '16px' }}>{user.role.toUpperCase()}</div>
                  </div>
                  <div>
                    <div style={{ fontWeight: '600', color: '#64748b', fontSize: '13px', marginBottom: '4px' }}>Account Status</div>
                    <div style={{ color: '#1e293b', fontSize: '16px' }}>
                      {user.is_approved ? '✓ Approved' : '⏳ Pending Approval'}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontWeight: '600', color: '#64748b', fontSize: '13px', marginBottom: '4px' }}>Public Key</div>
                    <div style={{ 
                      color: '#64748b', 
                      fontSize: '13px', 
                      fontFamily: 'monospace', 
                      background: '#f8fafc', 
                      padding: '12px', 
                      borderRadius: '6px',
                      wordBreak: 'break-all'
                    }}>
                      {user.public_key_pem ? user.public_key_pem.substring(0, 100) + '...' : 'Not available'}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* MFA Tab */}
            {profileTab === 'mfa' && (
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px' }}>
                  Two-Factor Authentication (MFA)
                </h3>
                <p style={{ color: '#64748b', marginBottom: '24px' }}>
                  Add an extra layer of security to your account by enabling MFA
                </p>

                {!mfaEnabled && !mfaSetupData && (
                  <div>
                    <div style={{ 
                      background: '#fef3c7', 
                      border: '1px solid #fcd34d', 
                      color: '#92400e', 
                      padding: '12px 16px', 
                      borderRadius: '8px', 
                      marginBottom: '16px'
                    }}>
                      ⚠️ MFA is currently disabled. Enable it for better security.
                    </div>
                    <button onClick={setupMFA} disabled={loading}>
                      {loading ? 'Setting up...' : '🔐 Enable MFA'}
                    </button>
                  </div>
                )}

                {mfaSetupData && (
                  <div>
                    <div style={{ marginBottom: '24px' }}>
                      <h4 style={{ margin: '0 0 12px 0', color: '#1e293b' }}>Scan QR Code</h4>
                      <img 
                        src={`data:image/png;base64,${mfaSetupData.qr_code}`} 
                        alt="MFA QR Code"
                        style={{ border: '1px solid #e2e8f0', borderRadius: '8px' }}
                      />
                      <p style={{ color: '#64748b', fontSize: '13px', marginTop: '8px' }}>
                        Manual Entry: <code style={{ background: '#f8fafc', padding: '4px 8px', borderRadius: '4px' }}>{mfaSetupData.secret}</code>
                      </p>
                    </div>

                    <div style={{ marginBottom: '24px' }}>
                      <h4 style={{ margin: '0 0 12px 0', color: '#1e293b' }}>Backup Codes</h4>
                      <div style={{ 
                        background: '#f8fafc', 
                        padding: '12px', 
                        borderRadius: '6px', 
                        fontFamily: 'monospace', 
                        fontSize: '13px',
                        display: 'grid',
                        gridTemplateColumns: 'repeat(2, 1fr)',
                        gap: '8px'
                      }}>
                        {mfaSetupData.backup_codes.map((code, i) => (
                          <div key={i}>{code}</div>
                        ))}
                      </div>
                      <p style={{ color: '#ef4444', fontSize: '13px', marginTop: '8px' }}>
                        ⚠️ Save these codes securely. You'll need them to access your account if you lose your device.
                      </p>
                    </div>

                    <div>
                      <label style={{ display: 'block', marginBottom: '8px', fontWeight: '600', color: '#475569' }}>
                        Enter Verification Code
                      </label>
                      <input 
                        type="text" 
                        placeholder="000000" 
                        id="mfa-token"
                        style={{ width: '200px', marginRight: '8px' }}
                      />
                      <button onClick={() => {
                        const token = document.getElementById('mfa-token').value
                        if (token) enableMFA(token)
                      }}>
                        ✓ Verify & Enable
                      </button>
                      <button 
                        onClick={() => setMfaSetupData(null)} 
                        className="secondary"
                        style={{ marginLeft: '8px' }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                {mfaEnabled && !mfaSetupData && (
                  <div>
                    <div style={{ 
                      background: '#d1fae5', 
                      border: '1px solid #6ee7b7', 
                      color: '#065f46', 
                      padding: '12px 16px', 
                      borderRadius: '8px', 
                      marginBottom: '16px'
                    }}>
                      ✓ MFA is enabled and protecting your account
                    </div>
                    <button onClick={disableMFA} className="secondary" disabled={loading}>
                      {loading ? 'Disabling...' : 'Disable MFA'}
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Audit Logs Tab */}
            {profileTab === 'audit' && (
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px' }}>
                  📊 Recent Activity ({auditLogs.length})
                </h3>
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Action</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Entity</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Details</th>
                        <th style={{ padding: '12px', color: '#64748b', fontWeight: '600', fontSize: '13px' }}>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.length === 0 ? (
                        <tr>
                          <td colSpan="4" style={{ padding: '24px', textAlign: 'center', color: '#94a3b8' }}>
                            No activity logs yet
                          </td>
                        </tr>
                      ) : (
                        auditLogs.map(log => (
                          <tr key={log.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                            <td style={{ padding: '12px' }}>
                              <span style={{
                                background: log.action.includes('delete') ? '#fee2e2' : 
                                           log.action.includes('login') ? '#dbeafe' :
                                           log.action.includes('upload') ? '#d1fae5' : '#f3f4f6',
                                color: log.action.includes('delete') ? '#991b1b' :
                                       log.action.includes('login') ? '#1e40af' :
                                       log.action.includes('upload') ? '#065f46' : '#374151',
                                padding: '4px 8px',
                                borderRadius: '6px',
                                fontSize: '12px',
                                fontWeight: '600'
                              }}>
                                {log.action}
                              </span>
                            </td>
                            <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                              {log.entity_type}
                            </td>
                            <td style={{ padding: '12px', color: '#1e293b', fontSize: '13px' }}>
                              {log.detail || '-'}
                            </td>
                            <td style={{ padding: '12px', color: '#64748b', fontSize: '13px' }}>
                              {new Date(log.created_at).toLocaleString()}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Trusted Devices Tab */}
            {profileTab === 'devices' && (
              <div className="card">
                <h3 style={{ margin: '0 0 16px 0', color: '#1e293b', fontSize: '20px' }}>
                  📱 Your Trusted Devices ({trustedDevices.length})
                </h3>
                <div style={{ display: 'grid', gap: '12px' }}>
                  {trustedDevices.length === 0 ? (
                    <p style={{ color: '#94a3b8', margin: 0 }}>No trusted devices yet</p>
                  ) : (
                    trustedDevices.map(device => (
                      <div 
                        key={device.id}
                        style={{
                          background: '#f8fafc',
                          padding: '16px',
                          borderRadius: '8px',
                          border: '1px solid #e2e8f0'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: '600', color: '#1e293b', marginBottom: '4px' }}>
                              {device.device_name}
                            </div>
                            <div style={{ fontSize: '12px', color: '#64748b', fontFamily: 'monospace' }}>
                              {device.device_fingerprint.substring(0, 32)}...
                            </div>
                            <div style={{ fontSize: '13px', color: '#64748b', marginTop: '8px' }}>
                              IP: {device.ip_address} • Last used: {new Date(device.last_used_at).toLocaleString()}
                            </div>
                          </div>
                          <div>
                            {device.is_trusted ? (
                              <span style={{
                                background: '#d1fae5',
                                color: '#065f46',
                                padding: '4px 12px',
                                borderRadius: '6px',
                                fontSize: '12px',
                                fontWeight: '600'
                              }}>
                                ✓ Trusted
                              </span>
                            ) : (
                              <span style={{
                                background: '#fee2e2',
                                color: '#991b1b',
                                padding: '4px 12px',
                                borderRadius: '6px',
                                fontSize: '12px',
                                fontWeight: '600'
                              }}>
                                ⚠ Pending
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

const root = createRoot(document.getElementById('root'))
root.render(<App />)
