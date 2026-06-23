import axios from 'axios'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000'

// Public API client (no authentication required)
export const publicApi = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})



// WebSocket client with authentication
export class WebSocketClient {
  private ws: WebSocket | null = null
  private url: string
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectDelay = 1000
  private onMessageCallback: ((data: any) => void) | null = null
  private onErrorCallback: ((error: Event) => void) | null = null
  private onCloseCallback: ((event: CloseEvent) => void) | null = null

  constructor(path: string) {
    this.url = `${WS_URL}${path}`
  }

  connect() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return
    }

    this.ws = new WebSocket(this.url)

    this.ws.onopen = () => {
      console.log('WebSocket connected')
      this.reconnectAttempts = 0
    }

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        this.onMessageCallback?.(data)
      } catch (error) {
        console.error('WebSocket message parse error:', error)
      }
    }

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      this.onErrorCallback?.(error)
    }

    this.ws.onclose = (event) => {
      console.log('WebSocket closed:', event.code, event.reason)
      this.onCloseCallback?.(event)
      
      // Attempt to reconnect if not a clean close
      if (event.code !== 1000 && this.reconnectAttempts < this.maxReconnectAttempts) {
        setTimeout(() => {
          this.reconnectAttempts++
          this.connect()
        }, this.reconnectDelay * this.reconnectAttempts)
      }
    }
  }

  onMessage(callback: (data: any) => void) {
    this.onMessageCallback = callback
  }

  onError(callback: (error: Event) => void) {
    this.onErrorCallback = callback
  }

  onClose(callback: (event: CloseEvent) => void) {
    this.onCloseCallback = callback
  }

  disconnect() {
    if (this.ws) {
      this.ws.close(1000, 'Client disconnecting')
      this.ws = null
    }
  }

  send(data: any) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    }
  }
}

