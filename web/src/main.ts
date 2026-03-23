import './styles.css'

type FileType =
  | 'cert'
  | 'key'
  | 'public-key'
  | 'combined'
  | 'pfx'
  | 'der'
  | 'base64'
  | 'p7b'
  | 'unknown'

type Summary = {
  File: string
  FileType: FileType
  Subject?: string
  Issuer?: string
  NotBefore?: string
  NotAfter?: string
  Serial?: string
  KeyType?: string
  PublicKeyAlgorithm?: string
  PublicKeyComment?: string
  SANs?: string[]
  SignatureAlgorithm?: string
  PublicKeyInfo?: string
  KeyUsage?: string[]
  ExtKeyUsage?: string[]
  IsCA?: boolean
  IsSelfSigned?: boolean
  Fingerprint?: string
}

type LintIssue = {
  severity: 'error' | 'warning'
  code: string
  message: string
}

type LintResult = {
  file: string
  issues: LintIssue[]
  clean: boolean
}

type Action = {
  id: string
  label: string
  description: string
}

type Analysis = {
  fileName: string
  fileType: FileType
  summary?: Summary
  lint?: LintResult
  certCount?: number
  passwordRequired?: boolean
  notes?: string[]
  actions: Action[]
}

type Output = {
  kind: 'text' | 'binary'
  name: string
  mime: string
  text?: string
  base64?: string
}

type Response = {
  ok: boolean
  error?: string
  analysis?: Analysis
  output?: Output
}

type Request = {
  op: string
  name?: string
  password?: string
  inputBase64: string
}

type LoadedInput = {
  name: string
  base64: string
  byteLength: number
  preview: string
}

declare global {
  interface Window {
    Go?: new () => {
      importObject: WebAssembly.Imports
      run(instance: WebAssembly.Instance): void
    }
    certconvInvoke?: (requestJson: string) => string
    certconvReady?: boolean
  }
}

const state: {
  mode: 'file' | 'paste'
  currentInput: LoadedInput | null
  currentAnalysis: Analysis | null
  currentOutput: Output | null
  activeActionId: string | null
  sourceViewMode: 'content' | 'one-line' | 'base64'
  wasmReady: boolean
  wasmPromise: Promise<void> | null
} = {
  mode: 'file',
  currentInput: null,
  currentAnalysis: null,
  currentOutput: null,
  activeActionId: null,
  sourceViewMode: 'content',
  wasmReady: false,
  wasmPromise: null,
}

const engineBadge = mustElement<HTMLSpanElement>('engine-badge')
const inputStatus = mustElement<HTMLSpanElement>('input-status')
const fileInput = mustElement<HTMLInputElement>('file-input')
const filePicker = mustElement<HTMLButtonElement>('file-picker')
const dropZone = mustElement<HTMLDivElement>('drop-zone')
const fileMeta = mustElement<HTMLSpanElement>('file-meta')
const pfxPasswordPanel = mustElement<HTMLDivElement>('pfx-password-panel')
const pfxPassword = mustElement<HTMLInputElement>('pfx-password')
const pfxUnlock = mustElement<HTMLButtonElement>('pfx-unlock')
const modeFile = mustElement<HTMLButtonElement>('mode-file')
const modePaste = mustElement<HTMLButtonElement>('mode-paste')
const filePane = mustElement<HTMLDivElement>('file-pane')
const pastePane = mustElement<HTMLDivElement>('paste-pane')
const pasteName = mustElement<HTMLInputElement>('paste-name')
const pasteInput = mustElement<HTMLTextAreaElement>('paste-input')
const analyzePaste = mustElement<HTMLButtonElement>('analyze-paste')
const workspaceEmpty = mustElement<HTMLDivElement>('workspace-empty')
const workspaceContent = mustElement<HTMLDivElement>('workspace-content')
const sourceMeta = mustElement<HTMLDivElement>('source-meta')
const sourcePreview = mustElement<HTMLPreElement>('source-preview')
const conversionList = mustElement<HTMLDivElement>('conversion-list')
const analysisEmpty = mustElement<HTMLDivElement>('analysis-empty')
const analysisContent = mustElement<HTMLDivElement>('analysis-content')
const analysisFile = mustElement<HTMLDivElement>('analysis-file')
const analysisNotes = mustElement<HTMLDivElement>('analysis-notes')
const summaryList = mustElement<HTMLDListElement>('summary-list')
const lintList = mustElement<HTMLDivElement>('lint-list')
const outputEmpty = mustElement<HTMLDivElement>('output-empty')
const outputContent = mustElement<HTMLDivElement>('output-content')
const outputName = mustElement<HTMLSpanElement>('output-name')
const outputKind = mustElement<HTMLSpanElement>('output-kind')
const outputPreview = mustElement<HTMLPreElement>('output-preview')
const downloadOutput = mustElement<HTMLButtonElement>('download-output')

void bootstrap()

async function bootstrap(): Promise<void> {
  wireUi()
  try {
    await ensureWasm()
    engineBadge.textContent = 'Engine ready'
    engineBadge.classList.add('is-ready')
    inputStatus.textContent = 'Ready. Drop a file or paste certificate text to begin.'
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to load WebAssembly.'
    engineBadge.textContent = message
    engineBadge.classList.add('is-error')
  }
}

function wireUi(): void {
  filePicker.addEventListener('click', () => fileInput.click())
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0]
    if (file) {
      await loadFile(file)
      fileInput.value = ''
    }
  })

  dropZone.addEventListener('dragenter', (event) => {
    event.preventDefault()
    dropZone.classList.add('is-dragging')
  })
  dropZone.addEventListener('dragover', (event) => {
    event.preventDefault()
    dropZone.classList.add('is-dragging')
  })
  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('is-dragging')
  })
  dropZone.addEventListener('drop', async (event) => {
    event.preventDefault()
    dropZone.classList.remove('is-dragging')
    const file = event.dataTransfer?.files?.[0]
    if (file) {
      await loadFile(file)
    }
  })
  dropZone.addEventListener('keydown', async (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      fileInput.click()
    }
  })

  modeFile.addEventListener('click', () => setMode('file'))
  modePaste.addEventListener('click', () => setMode('paste'))
  pfxUnlock.addEventListener('click', async () => {
    await analyzeCurrentInput()
  })
  pfxPassword.addEventListener('keydown', async (event) => {
    if (event.key === 'Enter') {
      event.preventDefault()
      await analyzeCurrentInput()
    }
  })

  analyzePaste.addEventListener('click', async () => {
    const text = pasteInput.value.trim()
    if (!text) {
      inputStatus.textContent = 'Paste certificate or bundle text first.'
      return
    }
    const name = pasteName.value.trim() || 'pasted.pem'
    const bytes = new TextEncoder().encode(text)
    state.currentInput = {
      name,
      base64: bytesToBase64(bytes),
      byteLength: bytes.byteLength,
      preview: buildInputPreview(bytes),
    }
    state.currentAnalysis = null
    inputStatus.textContent = `Loaded ${name} from pasted text.`
    renderInputMeta(name, bytes.byteLength)
    await analyzeCurrentInput()
  })

  for (const btn of document.querySelectorAll('.view-mode__button')) {
    btn.addEventListener('click', () => {
      const mode = (btn as HTMLElement).dataset.view as typeof state.sourceViewMode
      if (!mode) return
      state.sourceViewMode = mode
      for (const b of document.querySelectorAll('.view-mode__button')) {
        b.classList.toggle('is-active', (b as HTMLElement).dataset.view === mode)
      }
      updateSourcePreview()
    })
  }

  downloadOutput.addEventListener('click', () => {
    if (!state.currentOutput) {
      return
    }
    downloadGeneratedOutput(state.currentOutput)
  })

  const shortcutsOverlay = document.getElementById('shortcuts-overlay')!
  const shortcutsClose = document.getElementById('shortcuts-close')!
  shortcutsClose.addEventListener('click', () => shortcutsOverlay.classList.add('is-hidden'))

  document.addEventListener('keydown', (event) => {
    const tag = (document.activeElement?.tagName ?? '').toLowerCase()
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return

    switch (event.key) {
      case 'c': {
        const text = state.currentOutput?.text ?? state.currentOutput?.base64 ?? state.currentInput?.preview
        if (text) {
          void copyToClipboard(text).then((ok) => {
            if (ok) showToast('Copied to clipboard')
          })
        }
        break
      }
      case '1':
        document.getElementById('panel-input')?.scrollIntoView({ behavior: 'smooth' })
        break
      case '2':
        document.getElementById('panel-workspace')?.scrollIntoView({ behavior: 'smooth' })
        break
      case '3':
        document.getElementById('panel-details')?.scrollIntoView({ behavior: 'smooth' })
        break
      case '?':
        shortcutsOverlay.classList.toggle('is-hidden')
        break
      case 'Escape':
        if (!shortcutsOverlay.classList.contains('is-hidden')) {
          shortcutsOverlay.classList.add('is-hidden')
        }
        break
    }
  })
}

function setMode(mode: 'file' | 'paste'): void {
  state.mode = mode
  modeFile.classList.toggle('is-active', mode === 'file')
  modePaste.classList.toggle('is-active', mode === 'paste')
  filePane.classList.toggle('is-hidden', mode !== 'file')
  pastePane.classList.toggle('is-hidden', mode !== 'paste')
  if (mode !== 'file') {
    pfxPasswordPanel.classList.add('is-hidden')
    return
  }
  pfxPasswordPanel.classList.toggle('is-hidden', !hasCurrentPFXInput())
}

async function loadFile(file: File): Promise<void> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  state.currentInput = {
    name: file.name,
    base64: bytesToBase64(bytes),
    byteLength: bytes.byteLength,
    preview: buildInputPreview(bytes),
  }
  state.currentAnalysis = null
  inputStatus.textContent = `Loaded ${file.name}.`
  renderInputMeta(file.name, bytes.byteLength)
  setPFXPasswordVisibility(isPFXFileName(file.name), true)
  await analyzeCurrentInput()
}

async function analyzeCurrentInput(): Promise<void> {
  if (!state.currentInput) {
    return
  }
  inputStatus.textContent = `Analyzing ${state.currentInput.name}…`
  const response = await invoke({
    op: 'analyze',
    name: state.currentInput.name,
    password: currentPassword(),
    inputBase64: state.currentInput.base64,
  })
  if (!response.ok || !response.analysis) {
    inputStatus.textContent = response.error ?? 'Analysis failed.'
    return
  }
  if (response.analysis.passwordRequired) {
    inputStatus.textContent =
      currentPassword() === ''
        ? `Enter the PFX password for ${state.currentInput.name} and unlock again.`
        : `The supplied PFX password for ${state.currentInput.name} was not accepted.`
  } else {
    inputStatus.textContent = `Analyzed ${state.currentInput.name}.`
  }
  state.currentAnalysis = response.analysis
  state.currentOutput = null
  state.activeActionId = null
  state.sourceViewMode = 'content'
  for (const b of document.querySelectorAll('.view-mode__button')) {
    b.classList.toggle('is-active', (b as HTMLElement).dataset.view === 'content')
  }
  renderWorkspace(response.analysis)
  renderAnalysis(response.analysis)
  renderEmptyOutput()
}

async function invoke(request: Request): Promise<Response> {
  await ensureWasm()
  const raw = window.certconvInvoke?.(JSON.stringify(request))
  if (!raw) {
    throw new Error('certconv wasm did not register certconvInvoke.')
  }
  return JSON.parse(raw) as Response
}

async function ensureWasm(): Promise<void> {
  if (state.wasmReady) {
    return
  }
  if (state.wasmPromise) {
    return state.wasmPromise
  }

  state.wasmPromise = (async () => {
    await loadScript('./wasm_exec.js')
    if (!window.Go) {
      throw new Error('wasm_exec.js did not expose the Go runtime.')
    }

    const go = new window.Go()
    const response = await fetch('./certconv.wasm')
    if (!response.ok) {
      throw new Error(`Failed to fetch certconv.wasm (${response.status}).`)
    }
    const bytes = await response.arrayBuffer()
    const result = await WebAssembly.instantiate(bytes, go.importObject)
    go.run(result.instance)

    if (!window.certconvReady || !window.certconvInvoke) {
      throw new Error('Go WebAssembly runtime did not finish initialization.')
    }

    state.wasmReady = true
  })()

  return state.wasmPromise
}

function renderInputMeta(name: string, byteLength: number): void {
  fileMeta.textContent = `${name} · ${formatBytes(byteLength)}`
}

function renderWorkspace(analysis: Analysis): void {
  workspaceEmpty.classList.add('is-hidden')
  workspaceContent.classList.remove('is-hidden')

  sourceMeta.innerHTML = ''
  sourceMeta.append(
    statChip(`source / ${analysis.fileType}`),
    statChip(`size / ${state.currentInput ? formatBytes(state.currentInput.byteLength) : 'unknown'}`),
  )

  sourcePreview.textContent = state.currentInput?.preview ?? ''
  attachPreviewCopyButton(sourcePreview, () => sourcePreview.textContent ?? '')

  conversionList.innerHTML = ''
  for (const action of analysis.actions) {
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'conversion-card'
    button.dataset.actionId = action.id
    button.title = action.description

    const label = document.createElement('span')
    label.className = 'conversion-card__label'
    label.textContent = action.label

    const description = document.createElement('span')
    description.className = 'conversion-card__description'
    description.textContent = action.description

    button.append(label, description)
    button.addEventListener('click', async () => {
      await runAction(action)
    })
    conversionList.append(button)
  }
}

function renderAnalysis(analysis: Analysis): void {
  analysisEmpty.classList.add('is-hidden')
  analysisContent.classList.remove('is-hidden')
  setPFXPasswordVisibility(state.mode === 'file' && analysis.fileType === 'pfx', false)

  analysisFile.innerHTML = ''
  analysisFile.append(
    statChip(`type / ${analysis.fileType}`),
    statChip(`size / ${analysis.certCount ? `${analysis.certCount} cert block${analysis.certCount === 1 ? '' : 's'}` : 'single input'}`),
  )

  analysisNotes.innerHTML = ''
  for (const note of analysis.notes ?? []) {
    const item = document.createElement('p')
    item.className = 'note'
    item.textContent = note
    analysisNotes.append(item)
  }

  summaryList.innerHTML = ''
  const summaryCard = summaryList.closest('.card--summary')
  const existingSummaryCopy = summaryCard?.querySelector('.copy-button')
  if (existingSummaryCopy) existingSummaryCopy.remove()
  if (summaryCard && analysis.summary) {
    const header = summaryCard.querySelector('.card__header')
    if (header) header.append(createCopyButton(() => summaryToText(), 'Copy'))
  }
  if (analysis.summary) {
    appendSummaryRow('Subject', analysis.summary.Subject)
    appendSummaryRow('Issuer', analysis.summary.Issuer)
    appendSummaryRow('Not Before', analysis.summary.NotBefore)
    appendSummaryRow('Not After', analysis.summary.NotAfter)
    appendSummaryRow('Serial', analysis.summary.Serial)
    appendSummaryRow('Key Type', analysis.summary.KeyType)
    appendSummaryRow('Public Key', analysis.summary.PublicKeyInfo ?? analysis.summary.PublicKeyAlgorithm)
    appendSummaryRow('Signature', analysis.summary.SignatureAlgorithm)
    appendSummaryRow('Fingerprint', analysis.summary.Fingerprint)
    appendSummaryRow('SANs', analysis.summary.SANs?.join('\n'))
    appendSummaryRow('Key Usage', analysis.summary.KeyUsage?.join(', '))
    appendSummaryRow('Ext Key Usage', analysis.summary.ExtKeyUsage?.join(', '))
    if (analysis.summary.IsCA !== undefined) appendSummaryBadge('CA', analysis.summary.IsCA)
    if (analysis.summary.IsSelfSigned !== undefined) appendSummaryBadge('Self-Signed', analysis.summary.IsSelfSigned)
  } else {
    appendSummaryRow('Summary', fallbackSummaryMessage(analysis))
  }

  lintList.innerHTML = ''
  if (analysis.lint) {
    if (analysis.lint.clean) {
      lintList.append(lintBadge('clean', 'No lint findings'))
    } else {
      for (const issue of analysis.lint.issues) {
        lintList.append(lintBadge(issue.severity, `[${issue.code}] ${issue.message}`))
      }
    }
  } else {
    lintList.append(lintBadge('warning', 'Lint is only available for certificate inputs.'))
  }

  if (analysis.fileType === 'pfx' && analysis.passwordRequired) {
    pfxPassword.focus()
  }
}

async function runAction(action: Action): Promise<void> {
  if (!state.currentInput) {
    return
  }

  inputStatus.textContent = `${action.label}…`
  const response = await invoke({
    op: action.id,
    name: state.currentInput.name,
    password: currentPassword(),
    inputBase64: state.currentInput.base64,
  })
  if (!response.ok || !response.output) {
    inputStatus.textContent = response.error ?? `${action.label} failed.`
    return
  }

  inputStatus.textContent = `${action.label} complete.`
  state.currentOutput = response.output
  state.activeActionId = action.id
  updateActiveConversionButton()
  renderOutput(response.output)
}

function renderOutput(output: Output): void {
  outputEmpty.classList.add('is-hidden')
  outputContent.classList.remove('is-hidden')
  downloadOutput.classList.remove('is-hidden')
  outputName.textContent = output.name
  outputKind.textContent = output.kind === 'text' ? 'text output' : 'binary output'

  if (output.kind === 'text') {
    outputPreview.textContent = output.text ?? ''
    attachPreviewCopyButton(outputPreview, () => state.currentOutput?.text ?? '')
    return
  }

  const bytes = base64ToBytes(output.base64 ?? '')
  outputPreview.textContent = [
    `${formatBytes(bytes.byteLength)} ready to download.`,
    '',
    `First 32 bytes (hex):`,
    toHexPreview(bytes),
  ].join('\n')
  attachPreviewCopyButton(outputPreview, () => state.currentOutput?.base64 ?? '', 'Copy Base64')
}

function updateSourcePreview(): void {
  if (!state.currentInput) return
  switch (state.sourceViewMode) {
    case 'content':
      sourcePreview.textContent = state.currentInput.preview
      break
    case 'one-line':
      sourcePreview.textContent = toOneLine(state.currentInput.preview)
      break
    case 'base64':
      sourcePreview.textContent = state.currentInput.base64
      break
  }
  attachPreviewCopyButton(sourcePreview, () => sourcePreview.textContent ?? '')
}

function toOneLine(text: string): string {
  const lines = text.split('\n')
  const bodyLines: string[] = []
  let inBlock = false
  for (const line of lines) {
    if (line.startsWith('-----BEGIN ')) {
      inBlock = true
      continue
    }
    if (line.startsWith('-----END ')) {
      inBlock = false
      continue
    }
    if (inBlock) {
      bodyLines.push(line.trim())
    }
  }
  if (bodyLines.length === 0) {
    return text.replace(/\n/g, '')
  }
  return bodyLines.join('')
}

function updateActiveConversionButton(): void {
  for (const btn of conversionList.querySelectorAll('.conversion-card')) {
    const el = btn as HTMLElement
    el.classList.toggle('is-active', el.dataset.actionId === state.activeActionId)
  }
}

function renderEmptyOutput(): void {
  outputEmpty.classList.remove('is-hidden')
  outputContent.classList.add('is-hidden')
  downloadOutput.classList.add('is-hidden')
  outputPreview.textContent = ''
}

function downloadGeneratedOutput(output: Output): void {
  const blob =
    output.kind === 'text'
      ? new Blob([output.text ?? ''], { type: output.mime })
      : new Blob([toArrayBuffer(base64ToBytes(output.base64 ?? ''))], { type: output.mime })

  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = output.name
  anchor.click()
  URL.revokeObjectURL(url)
}

function appendSummaryRow(label: string, value?: string): void {
  if (!value) {
    return
  }
  const row = document.createElement('div')
  row.className = 'summary-row'
  if (isWideSummaryField(label, value)) {
    row.classList.add('summary-row--wide')
  }
  const dt = document.createElement('dt')
  dt.textContent = label
  const dd = document.createElement('dd')
  dd.textContent = value
  row.append(dt, dd)
  summaryList.append(row)
}

function appendSummaryBadge(label: string, value: boolean): void {
  const row = document.createElement('div')
  row.className = 'summary-row'
  const dt = document.createElement('dt')
  dt.textContent = label
  const dd = document.createElement('dd')
  const badge = document.createElement('span')
  badge.className = `summary-badge summary-badge--${value ? 'yes' : 'no'}`
  badge.textContent = value ? 'Yes' : 'No'
  dd.append(badge)
  row.append(dt, dd)
  summaryList.append(row)
}

function isWideSummaryField(label: string, value: string): boolean {
  return ['Subject', 'Issuer', 'Fingerprint', 'SANs', 'Public Key'].includes(label) || value.length > 64
}

function fallbackSummaryMessage(analysis: Analysis): string {
  if (analysis.fileType === 'pfx' && analysis.passwordRequired) {
    return 'Enter the PFX/P12 password to inspect the certificate inside this container.'
  }

  switch (analysis.fileType) {
    case 'pfx':
      return 'This PFX/P12 could not be summarized in the browser build.'
    case 'p7b':
      return 'PKCS#7/P7B summary is not available in the browser build yet.'
    case 'base64':
      return 'This input looks like raw base64. Decode it first to inspect the underlying certificate material.'
    case 'unknown':
      return 'The browser build could not confidently classify this input.'
    default:
      return 'No pure-Go summary is available for this file type in the browser build.'
  }
}

function setPFXPasswordVisibility(visible: boolean, clearPassword: boolean): void {
  const shouldShow = visible && state.mode === 'file'
  pfxPasswordPanel.classList.toggle('is-hidden', !shouldShow)
  if (clearPassword) {
    pfxPassword.value = ''
  }
}

function currentPassword(): string {
  if (!hasCurrentPFXInput()) {
    return ''
  }
  return pfxPassword.value
}

function hasCurrentPFXInput(): boolean {
  return (
    state.currentInput !== null &&
    (isPFXFileName(state.currentInput.name) || state.currentAnalysis?.fileType === 'pfx')
  )
}

function isPFXFileName(name: string): boolean {
  return /\.(pfx|p12)$/i.test(name.trim())
}

function lintBadge(kind: 'clean' | 'warning' | 'error', message: string): HTMLElement {
  const item = document.createElement('div')
  item.className = `lint-badge lint-badge--${kind}`
  item.textContent = message
  return item
}

function statChip(text: string): HTMLElement {
  const chip = document.createElement('span')
  chip.className = 'stat-chip'
  chip.textContent = text
  return chip
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

function buildInputPreview(bytes: Uint8Array): string {
  if (bytes.byteLength === 0) {
    return '[Empty input]'
  }

  if (looksLikeTextInput(bytes)) {
    const text = new TextDecoder().decode(bytes)
    const maxLength = 24000
    if (text.length <= maxLength) {
      return text
    }
    return `${text.slice(0, maxLength)}\n\n... (truncated, ${formatBytes(bytes.byteLength)} total)`
  }

  return [
    `[Binary input, ${formatBytes(bytes.byteLength)}]`,
    '',
    'First 64 bytes (hex):',
    formatHexBlocks(bytes.slice(0, 64), 16),
  ].join('\n')
}

function base64ToBytes(base64Value: string): Uint8Array {
  const binary = atob(base64Value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function toHexPreview(bytes: Uint8Array): string {
  return Array.from(bytes.slice(0, 32))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join(' ')
}

function formatHexBlocks(bytes: Uint8Array, width: number): string {
  const parts: string[] = []
  for (let i = 0; i < bytes.length; i += width) {
    const slice = bytes.slice(i, i + width)
    parts.push(Array.from(slice).map((byte) => byte.toString(16).padStart(2, '0')).join(' '))
  }
  return parts.join('\n')
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

function formatBytes(size: number): string {
  if (size < 1024) {
    return `${size} B`
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`
  }
  return `${(size / (1024 * 1024)).toFixed(2)} MB`
}

function looksLikeTextInput(bytes: Uint8Array): boolean {
  const sample = bytes.slice(0, Math.min(bytes.length, 512))
  let readable = 0
  for (const byte of sample) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
      readable += 1
    }
  }
  return readable / sample.length > 0.9
}

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${src}"]`)
    if (existing) {
      resolve()
      return
    }

    const script = document.createElement('script')
    script.src = src
    script.async = true
    script.onload = () => resolve()
    script.onerror = () => reject(new Error(`Failed to load ${src}.`))
    document.head.append(script)
  })
}

function mustElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id)
  if (!element) {
    throw new Error(`Missing required element #${id}`)
  }
  return element as T
}

let toastTimer: ReturnType<typeof setTimeout> | null = null

function showToast(message: string, durationMs = 2000): void {
  const toast = document.getElementById('toast')
  if (!toast) return
  toast.textContent = message
  toast.classList.remove('is-hidden')
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => {
    toast.classList.add('is-hidden')
    toastTimer = null
  }, durationMs)
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    const textarea = document.createElement('textarea')
    textarea.value = text
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.append(textarea)
    textarea.select()
    const ok = document.execCommand('copy')
    textarea.remove()
    return ok
  }
}

function attachPreviewCopyButton(pre: HTMLPreElement, getText: () => string, label = 'Copy'): void {
  let wrapper = pre.parentElement
  if (!wrapper?.classList.contains('preview-wrap')) {
    wrapper = document.createElement('div')
    wrapper.className = 'preview-wrap'
    pre.parentElement!.insertBefore(wrapper, pre)
    wrapper.append(pre)
  }
  const existing = wrapper.querySelector('.copy-button')
  if (existing) existing.remove()
  wrapper.append(createCopyButton(getText, label))
}

function createCopyButton(getText: () => string, label = 'Copy'): HTMLButtonElement {
  const button = document.createElement('button')
  button.type = 'button'
  button.className = 'copy-button'
  button.textContent = label
  button.addEventListener('click', async () => {
    const text = getText()
    if (!text) return
    const ok = await copyToClipboard(text)
    if (ok) {
      button.textContent = 'Copied!'
      showToast('Copied to clipboard')
      setTimeout(() => { button.textContent = label }, 1500)
    }
  })
  return button
}

function summaryToText(): string {
  if (!state.currentAnalysis?.summary) return ''
  const s = state.currentAnalysis.summary
  const lines: string[] = []
  if (s.Subject) lines.push(`Subject: ${s.Subject}`)
  if (s.Issuer) lines.push(`Issuer: ${s.Issuer}`)
  if (s.NotBefore) lines.push(`Not Before: ${s.NotBefore}`)
  if (s.NotAfter) lines.push(`Not After: ${s.NotAfter}`)
  if (s.Serial) lines.push(`Serial: ${s.Serial}`)
  if (s.KeyType) lines.push(`Key Type: ${s.KeyType}`)
  if (s.PublicKeyInfo ?? s.PublicKeyAlgorithm) lines.push(`Public Key: ${s.PublicKeyInfo ?? s.PublicKeyAlgorithm}`)
  if (s.SignatureAlgorithm) lines.push(`Signature: ${s.SignatureAlgorithm}`)
  if (s.Fingerprint) lines.push(`Fingerprint: ${s.Fingerprint}`)
  if (s.SANs?.length) lines.push(`SANs: ${s.SANs.join(', ')}`)
  if (s.KeyUsage?.length) lines.push(`Key Usage: ${s.KeyUsage.join(', ')}`)
  if (s.ExtKeyUsage?.length) lines.push(`Ext Key Usage: ${s.ExtKeyUsage.join(', ')}`)
  if (s.IsCA !== undefined) lines.push(`CA: ${s.IsCA ? 'Yes' : 'No'}`)
  if (s.IsSelfSigned !== undefined) lines.push(`Self-Signed: ${s.IsSelfSigned ? 'Yes' : 'No'}`)
  return lines.join('\n')
}
