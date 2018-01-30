package collectd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/signalfx/golib/datapoint"
	"github.com/signalfx/golib/event"
	"github.com/signalfx/metricproxy/protocol/collectd"
	"github.com/signalfx/neo-agent/utils"
)

type WriteHTTPServer struct {
	dpCallback    func([]*datapoint.Datapoint)
	eventCallback func([]*event.Event)
	ipAddr        string
	port          uint16
	server        *http.Server
}

// NewServer creates and starts a write server
func NewWriteHTTPServer(ipAddr string, port uint16,
	dpCallback func([]*datapoint.Datapoint), eventCallback func([]*event.Event)) (*WriteHTTPServer, error) {

	inst := &WriteHTTPServer{
		ipAddr:        ipAddr,
		port:          port,
		dpCallback:    dpCallback,
		eventCallback: eventCallback,
		server: &http.Server{
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 1 * time.Second,
		},
	}
	inst.server.Handler = inst

	return inst, nil
}

func (s *WriteHTTPServer) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.ipAddr, s.port))
	if err != nil {
		return err
	}

	go s.server.Serve(listener)
	return nil
}

// Shutdown stops the write server immediately
func (s *WriteHTTPServer) Shutdown() error {
	return s.server.Close()
}

func (s *WriteHTTPServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var writeBody collectd.JSONWriteBody
	err := json.NewDecoder(req.Body).Decode(&writeBody)
	if err != nil {
		log.WithError(err).Error("Could not decode body of write_http request")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// This is yet another way that collectd plugins can tell the agent what
	// the monitorID is.  This is specifically useful for the notifications
	// emitted by the metadata plugin.
	monitorID := req.URL.Query().Get("monitorID")

	var events []*event.Event
	// Preallocate space for dps
	dps := make([]*datapoint.Datapoint, 0, len(writeBody)*2)
	for _, f := range writeBody {
		if f.Time != nil && f.Severity != nil && f.Message != nil {
			event := collectd.NewEvent(f, nil)
			if monitorID != "" {
				event.Properties["monitorID"] = monitorID
			}
			events = append(events, event)
		} else {
			for i := range f.Dsnames {
				if i < len(f.Dstypes) && i < len(f.Values) && f.Values[i] != nil {
					dp := collectd.NewDatapoint(f, uint(i), nil)
					if monitorID != "" {
						dp.Meta["monitorID"] = monitorID
					}
					dp.Meta = utils.StringInterfaceMapToAllInterfaceMap(f.Meta)
					dps = append(dps, dp)
				}
			}
		}
	}

	if len(events) > 0 {
		s.eventCallback(events)
	}
	if len(dps) > 0 {
		s.dpCallback(dps)
	}

	rw.Write([]byte(`"OK"`))
}
