package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type wsMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type hub struct {
	clients   map[*client]bool
	register  chan *client
	unregister chan *client
	broadcast chan []byte
	logger    *slog.Logger
}

type client struct {
	hub  *hub
	conn *websocket.Conn
	send chan []byte
}

func newHub(logger *slog.Logger) *hub {
	return &hub{
		clients:   map[*client]bool{},
		register:  make(chan *client),
		unregister: make(chan *client),
		broadcast: make(chan []byte, 1024),
		logger:    logger,
	}
}

func (h *hub) run() {
	for {
		select {
		case c := <-h.register:
			h.clients[c] = true
		case c := <-h.unregister:
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}
		case msg := <-h.broadcast:
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					close(c.send)
					delete(h.clients, c)
				}
			}
		}
	}
}

var upgrader = websocket.Upgrader{
	HandshakeTimeout:  10 * time.Second,
	ReadBufferSize:    4096,
	WriteBufferSize:   4096,
	CheckOrigin:       func(r *http.Request) bool { return true }, // SPA local
	EnableCompression: true,
}

func (h *hub) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("ws upgrade", slog.String("err", err.Error()))
		return
	}
	c := &client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}
	h.register <- c
	go c.writePump()
	go c.readPump()
}

func (c *client) readPump() {
	defer func() {
		c.hub.unregister <- c
		_ = c.conn.Close()
	}()
	c.conn.SetReadLimit(4096)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (c *client) writePump() {
	ticker := time.NewTicker(25 * time.Second)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			if _, err := w.Write(msg); err != nil {
				return
			}
			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, []byte("ping")); err != nil {
				return
			}
		}
	}
}

// helper
func marshalWS(t string, v any) []byte {
	b, _ := json.Marshal(wsMessage{Type: t, Data: v})
	return b
}


