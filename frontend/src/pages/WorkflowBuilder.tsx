import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import ReactFlow, {
  ReactFlowProvider, Background, Controls, MiniMap,
  addEdge, useNodesState, useEdgesState,
  Handle, Position,
} from 'reactflow'
import type { Connection, Edge, Node, NodeProps, ReactFlowInstance } from 'reactflow'
import 'reactflow/dist/style.css'
import { ArrowLeft, Play, Save, Zap, GitBranch, Bolt } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../stores/auth'

const CATEGORY_COLOR: Record<string, string> = {
  trigger: '#22c55e',
  logic:   '#fbbf24',
  action:  '#60a5fa',
}
const CATEGORY_ICON: Record<string, any> = {
  trigger: Zap,
  logic:   GitBranch,
  action:  Bolt,
}

function FlowNode({ data, type, selected }: NodeProps) {
  const category = String(type).split('.')[0]
  const color = CATEGORY_COLOR[category] || '#94a3b8'
  const isTrigger = category === 'trigger'
  const isCondition = type === 'logic.condition'
  const Icon = CATEGORY_ICON[category] || Bolt

  return (
    <div
      style={{
        minWidth: 170, borderRadius: 8, padding: '10px 12px',
        background: 'rgba(15,20,32,0.95)',
        border: `1px solid ${selected ? color : 'rgba(255,255,255,0.1)'}`,
        boxShadow: selected ? `0 0 0 2px ${color}33` : 'none',
      }}
    >
      {!isTrigger && <Handle type="target" position={Position.Left} style={{ background: color }} />}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <Icon size={12} color={color} />
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)' }}>{data.label}</span>
      </div>
      {isCondition ? (
        <>
          <Handle type="source" position={Position.Right} id="true" style={{ top: '35%', background: '#22c55e' }} />
          <Handle type="source" position={Position.Right} id="false" style={{ top: '65%', background: '#f43f5e' }} />
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-3)', marginTop: 4 }}>
            <span>true</span><span>false</span>
          </div>
        </>
      ) : (
        <Handle type="source" position={Position.Right} style={{ background: color }} />
      )}
    </div>
  )
}

let idCounter = 0
function nextId() {
  idCounter += 1
  return `n${Date.now()}_${idCounter}`
}

export default function WorkflowBuilder() {
  const { id } = useParams()
  const isNew = !id
  const navigate = useNavigate()
  const qc = useQueryClient()
  const wrapperRef = useRef<HTMLDivElement>(null)
  const [rfInstance, setRfInstance] = useState<ReactFlowInstance | null>(null)

  const [name, setName] = useState('New workflow')
  const [description, setDescription] = useState('')
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>([])

  const { data: nodeTypesData } = useQuery({
    queryKey: ['node-types'],
    queryFn: () => api.listNodeTypes().then((r) => r.data.node_types as any[]),
  })
  const nodeCatalog = nodeTypesData || []

  const { data: workflow } = useQuery({
    queryKey: ['workflow', id],
    queryFn: () => api.getWorkflow(id!).then((r) => r.data),
    enabled: !isNew,
  })

  useEffect(() => {
    if (workflow) {
      setName(workflow.name)
      setDescription(workflow.description || '')
      setNodes(workflow.nodes || [])
      setEdges(workflow.edges || [])
    }
  }, [workflow])

  const nodeTypes = useMemo(() => {
    const map: Record<string, any> = {}
    for (const n of nodeCatalog) map[n.type] = FlowNode
    return map
  }, [nodeCatalog.length])

  const onConnect = useCallback(
    (conn: Connection) => setEdges((eds) => addEdge({ ...conn, id: `e${conn.source}-${conn.target}-${conn.sourceHandle || ''}` }, eds)),
    [setEdges],
  )

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault()
      const nodeType = event.dataTransfer.getData('application/reactflow-type')
      const label = event.dataTransfer.getData('application/reactflow-label')
      if (!nodeType || !rfInstance || !wrapperRef.current) return

      const bounds = wrapperRef.current.getBoundingClientRect()
      const position = rfInstance.project({ x: event.clientX - bounds.left, y: event.clientY - bounds.top })
      const catalogEntry = nodeCatalog.find((n) => n.type === nodeType)
      const defaultConfig: Record<string, any> = {}
      for (const f of catalogEntry?.config_schema || []) defaultConfig[f.key] = f.default ?? ''

      const newNode: Node = {
        id: nextId(),
        type: nodeType,
        position,
        data: { label: label || nodeType, config: defaultConfig },
      }
      setNodes((nds) => nds.concat(newNode))
    },
    [rfInstance, nodeCatalog, setNodes],
  )

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'move'
  }, [])

  const selectedNode = nodes.find((n) => n.id === selectedNodeId)
  const selectedCatalog = selectedNode ? nodeCatalog.find((n) => n.type === selectedNode.type) : null

  const updateSelectedConfig = (key: string, value: any) => {
    setNodes((nds) =>
      nds.map((n) =>
        n.id === selectedNodeId
          ? { ...n, data: { ...n.data, config: { ...n.data.config, [key]: value } } }
          : n,
      ),
    )
  }

  function deriveTrigger() {
    const start = nodes.find((n) => String(n.type).startsWith('trigger.'))
    if (!start) return { trigger_type: 'manual', trigger_config: {} }
    const kind = String(start.type).split('.')[1] || 'manual'
    return { trigger_type: kind, trigger_config: start.data?.config || {} }
  }

  const saveMutation = useMutation({
    mutationFn: () => {
      const { trigger_type, trigger_config } = deriveTrigger()
      const payload = { name, description, trigger_type, trigger_config, nodes, edges }
      return isNew ? api.createWorkflow(payload) : api.updateWorkflow(id!, payload)
    },
    onSuccess: (res) => {
      toast.success('Workflow saved')
      qc.invalidateQueries({ queryKey: ['workflows'] })
      if (isNew) navigate(`/soar/${res.data.id}/edit`, { replace: true })
    },
    onError: () => toast.error('Failed to save workflow'),
  })

  const runMutation = useMutation({
    mutationFn: () => api.runWorkflow(id!),
    onSuccess: () => toast.success('Workflow run queued'),
    onError: () => toast.error('Failed to queue run'),
  })

  const grouped = useMemo(() => {
    const g: Record<string, any[]> = { trigger: [], logic: [], action: [] }
    for (const n of nodeCatalog) (g[n.category] || (g[n.category] = [])).push(n)
    return g
  }, [nodeCatalog])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
      {/* ── Header ── */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1 }}>
          <button className="btn-secondary" onClick={() => navigate('/soar')}>
            <ArrowLeft size={13} />
          </button>
          <div style={{ flex: 1 }}>
            <input
              className="input"
              style={{ fontSize: 15, fontWeight: 600, marginBottom: 4, width: '100%' }}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Workflow name"
            />
            <input
              className="input"
              style={{ fontSize: 12, width: '100%' }}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Description"
            />
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {!isNew && (
            <button className="btn-secondary" disabled={runMutation.isPending} onClick={() => runMutation.mutate()}>
              <Play size={13} /> Run now
            </button>
          )}
          <button className="btn-primary" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate()}>
            <Save size={13} /> Save
          </button>
        </div>
      </div>

      {/* ── Builder ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr 240px', gap: 12, flex: 1, minHeight: 520 }}>

        {/* Palette */}
        <div className="card" style={{ padding: 12, overflowY: 'auto' }}>
          {Object.entries(grouped).map(([category, items]) => (
            <div key={category} style={{ marginBottom: 14 }}>
              <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-3)', marginBottom: 6 }}>
                {category}
              </p>
              {items.map((n) => (
                <div
                  key={n.type}
                  draggable
                  onDragStart={(e) => {
                    e.dataTransfer.setData('application/reactflow-type', n.type)
                    e.dataTransfer.setData('application/reactflow-label', n.label)
                  }}
                  title={n.description}
                  style={{
                    fontSize: 11, padding: '6px 8px', marginBottom: 4, borderRadius: 6, cursor: 'grab',
                    background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)',
                    color: 'var(--text-2)',
                  }}
                >
                  {n.label}
                </div>
              ))}
            </div>
          ))}
        </div>

        {/* Canvas */}
        <div ref={wrapperRef} className="card" style={{ padding: 0 }}>
          <ReactFlowProvider>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onInit={setRfInstance}
              onDrop={onDrop}
              onDragOver={onDragOver}
              onNodeClick={(_, node) => setSelectedNodeId(node.id)}
              onPaneClick={() => setSelectedNodeId(null)}
              nodeTypes={nodeTypes}
              fitView
            >
              <Background color="#334155" gap={18} />
              <Controls />
              <MiniMap style={{ background: '#0b101a' }} maskColor="rgba(0,0,0,0.6)" />
            </ReactFlow>
          </ReactFlowProvider>
        </div>

        {/* Config panel */}
        <div className="card" style={{ padding: 12, overflowY: 'auto' }}>
          {!selectedNode ? (
            <p style={{ fontSize: 12, color: 'var(--text-3)' }}>Select a node to edit its configuration.</p>
          ) : (
            <>
              <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)', marginBottom: 4 }}>
                {selectedNode.data.label}
              </p>
              <p style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 12 }}>{selectedCatalog?.description}</p>
              {(selectedCatalog?.config_schema || []).map((field: any) => (
                <div key={field.key} style={{ marginBottom: 10 }}>
                  <label style={{ fontSize: 10, color: 'var(--text-3)', display: 'block', marginBottom: 3 }}>
                    {field.label}
                  </label>
                  {field.type === 'select' ? (
                    <select
                      className="input"
                      style={{ width: '100%', fontSize: 12 }}
                      value={selectedNode.data.config?.[field.key] ?? field.default}
                      onChange={(e) => updateSelectedConfig(field.key, e.target.value)}
                    >
                      {field.options.map((opt: string) => (
                        <option key={opt} value={opt}>{opt}</option>
                      ))}
                    </select>
                  ) : (
                    <input
                      className="input"
                      style={{ width: '100%', fontSize: 12 }}
                      type={field.type === 'number' ? 'number' : 'text'}
                      value={selectedNode.data.config?.[field.key] ?? field.default}
                      onChange={(e) => updateSelectedConfig(field.key, field.type === 'number' ? Number(e.target.value) : e.target.value)}
                    />
                  )}
                </div>
              ))}
              {(selectedCatalog?.config_schema || []).length === 0 && (
                <p style={{ fontSize: 11, color: 'var(--text-3)' }}>This node has no configuration.</p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
