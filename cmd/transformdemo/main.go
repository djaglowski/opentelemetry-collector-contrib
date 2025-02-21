package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/websocket"
	"github.com/open-telemetry/opamp-go/protobufs"
	"google.golang.org/protobuf/proto"
)

const (
	transformCapability = "transform"
	transformMsgType    = "statements"
	opampSubprotocol    = "v1.opamp.io"
)

type server struct {
	upgrader     websocket.Upgrader
	clients      map[*websocket.Conn]struct{}
	clientsMutex sync.RWMutex
	configFile   string
	watcher      *fsnotify.Watcher
}

func newServer(configFile string) (*server, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	return &server{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				log.Printf("Checking origin: %s", r.Header.Get("Origin"))
				return true
			},
			Subprotocols: []string{opampSubprotocol},
		},
		clients:    make(map[*websocket.Conn]struct{}),
		configFile: configFile,
		watcher:    watcher,
	}, nil
}

func (s *server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received WebSocket connection request from %s", r.RemoteAddr)
	log.Printf("Request headers:")
	for k, v := range r.Header {
		log.Printf("  %s: %v", k, v)
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("New client connected from %s with protocol %s", remoteAddr, conn.Subprotocol())

	s.clientsMutex.Lock()
	s.clients[conn] = struct{}{}
	clientCount := len(s.clients)
	s.clientsMutex.Unlock()
	log.Printf("Total connected clients: %d", clientCount)

	defer func() {
		s.clientsMutex.Lock()
		delete(s.clients, conn)
		clientCount := len(s.clients)
		s.clientsMutex.Unlock()
		log.Printf("Client %s disconnected. Total connected clients: %d", remoteAddr, clientCount)
	}()

	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error from %s: %v", remoteAddr, err)
			}
			break
		}

		// Handle binary messages (Protocol Buffers)
		if messageType == websocket.BinaryMessage {
			log.Printf("Received binary message from %s: length=%d bytes", remoteAddr, len(msg))

			// Try parsing as AgentToServer message
			var agentMsg protobufs.AgentToServer
			if err := proto.Unmarshal(msg, &agentMsg); err != nil {
				continue
			}

			// Handle agent description
			if agentMsg.AgentDescription != nil {
				log.Printf("Client %s reported description: %+v", remoteAddr, agentMsg.AgentDescription)
			}

			// Handle effective config
			if agentMsg.EffectiveConfig != nil {
				log.Printf("Client %s reported effective config", remoteAddr)
			}

			// Handle health status
			if agentMsg.Health != nil {
				log.Printf("Client %s reported health status: healthy=%v", remoteAddr, agentMsg.Health.Healthy)
			}

			continue
		}

		// Handle text messages (JSON)
		var message struct {
			Type string `json:"type"`
			Body string `json:"body"`
		}
		if err := json.Unmarshal(msg, &message); err != nil {
			continue
		}

		if message.Type == "register_capability" && message.Body == transformCapability {
			log.Printf("Client %s registered transform capability", remoteAddr)
		}
	}
}

func (s *server) sendCurrentConfig(conn *websocket.Conn) error {
	content, err := os.ReadFile(s.configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	log.Printf("Read config file content: %s", string(content))

	// Send as a custom message in the OpAMP protocol format
	serverMsg := &protobufs.ServerToAgent{
		InstanceUid: []byte("transform-demo"),
		CustomMessage: &protobufs.CustomMessage{
			Capability: transformCapability,
			Type:       transformMsgType,
			Data:       content,
		},
	}

	data, err := proto.Marshal(serverMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	log.Printf("Sending config message: length=%d bytes", len(data))
	return conn.WriteMessage(websocket.BinaryMessage, data)
}

func (s *server) broadcastConfig() {
	s.clientsMutex.RLock()
	clientCount := len(s.clients)
	s.clientsMutex.RUnlock()

	if clientCount == 0 {
		log.Printf("No clients connected, skipping config broadcast")
		return
	}

	log.Printf("Broadcasting config update to %d clients", clientCount)

	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	for conn := range s.clients {
		remoteAddr := conn.RemoteAddr().String()
		if err := s.sendCurrentConfig(conn); err != nil {
			log.Printf("Failed to send config to %s: %v", remoteAddr, err)
		} else {
			log.Printf("Successfully sent config to %s", remoteAddr)
		}
	}
}

func (s *server) watchConfig() error {
	if err := s.watcher.Add(s.configFile); err != nil {
		return fmt.Errorf("failed to watch config file: %w", err)
	}

	log.Printf("Started watching config file: %s", s.configFile)

	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Printf("Config file modified: %s, operation: %s", event.Name, event.Op)
				time.Sleep(100 * time.Millisecond)
				s.broadcastConfig()
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func main() {
	var (
		addr       = flag.String("addr", ":4320", "WebSocket server address")
		configFile = flag.String("config", "", "Path to statements file to watch")
	)
	flag.Parse()

	if *configFile == "" {
		log.Fatal("Must specify a config file to watch")
	}

	absConfigFile, err := filepath.Abs(*configFile)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}

	if _, err := os.Stat(absConfigFile); os.IsNotExist(err) {
		log.Fatalf("Config file does not exist: %s", absConfigFile)
	}

	srv, err := newServer(absConfigFile)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer srv.watcher.Close()

	go func() {
		if err := srv.watchConfig(); err != nil {
			log.Printf("Config watcher stopped: %v", err)
		}
	}()

	http.HandleFunc("/ws", srv.handleWebSocket)
	server := &http.Server{Addr: *addr}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Failed to shutdown server: %v", err)
		}
	}()

	log.Printf("Starting OpAMP server on %s", *addr)
	log.Printf("Watching config file: %s", absConfigFile)
	log.Printf("Waiting for OpAMP clients to connect...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Failed to start server: %v", err)
	}
}
