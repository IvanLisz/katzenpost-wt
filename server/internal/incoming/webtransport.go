package incoming

import (
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

const (
	webTransportFrameMagic = "KPWT"
	webTransportVersion    = 1
	webTransportHeaderLen  = 12
	webTransportMaxPayload = 64 * 1024 * 1024
	webTransportReplyWait  = 45 * time.Second

	webTransportFramePing          = 1
	webTransportFrameGetConsensus  = 2
	webTransportFrameSendPacket    = 3
	webTransportFrameSendWithReply = 4
	webTransportFrameRegisterRecv  = 5

	webTransportFramePong      = 0x81
	webTransportFrameConsensus = 0x82
	webTransportFramePacketAck = 0x83
	webTransportFrameSurbReply = 0x84
	webTransportFrameRecvAck   = 0x85

	webTransportStatusOK       uint16 = 0
	webTransportStatusNotFound uint16 = 1
	webTransportStatusGone     uint16 = 2
	webTransportStatusError    uint16 = 0xffff
)

type webTransportListener struct {
	*listener

	server *webtransport.Server
}

type webTransportConn struct {
	stream *webtransport.Stream
	sess   *webtransport.Session
	local  net.Addr
	remote net.Addr
}

type webTransportAddr string

func (a webTransportAddr) Network() string { return "webtransport" }
func (a webTransportAddr) String() string  { return string(a) }

type prefixedConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if c.prefix != nil && c.prefix.Len() > 0 {
		return c.prefix.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *webTransportConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *webTransportConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c *webTransportConn) Close() error {
	streamErr := c.stream.Close()
	sessionErr := c.sess.CloseWithError(0, "")
	if streamErr != nil {
		return streamErr
	}
	return sessionErr
}

func (c *webTransportConn) Context() context.Context {
	return c.sess.Context()
}

func (c *webTransportConn) LocalAddr() net.Addr {
	return c.local
}

func (c *webTransportConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *webTransportConn) SetDeadline(t time.Time) error {
	if err := c.stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}

func (c *webTransportConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *webTransportConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (l *webTransportListener) Halt() {
	l.server.Close()
	l.Worker.Halt()
	close(l.closeAllCh)
	l.closeAllWg.Wait()
}

// NewWebTransport creates a WebTransport listener that feeds one reliable
// bidirectional stream per WebTransport session into the existing wire handler.
func NewWebTransport(glue glue.Glue, incomingCh chan<- interface{}, id int, cfg *config.WebTransport) (glue.Listener, error) {
	base := &listener{
		glue:       glue,
		log:        glue.LogBackend().GetLogger("listener:webtransport"),
		conns:      list.New(),
		incomingCh: incomingCh,
		closeAllCh: make(chan interface{}),
	}

	wt := &webTransportListener{listener: base}
	mux := http.NewServeMux()
	h3Server := &http3.Server{
		Addr:      cfg.BindAddress,
		Handler:   mux,
		TLSConfig: &tls.Config{NextProtos: []string{http3.NextProtoH3}},
	}
	webtransport.ConfigureHTTP3Server(h3Server)
	wt.server = &webtransport.Server{
		H3:          h3Server,
		CheckOrigin: func(*http.Request) bool { return true },
	}

	mux.HandleFunc(cfg.Path, func(w http.ResponseWriter, r *http.Request) {
		sess, err := wt.server.Upgrade(w, r)
		if err != nil {
			wt.log.Warningf("WebTransport upgrade failed: %v", err)
			return
		}
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			wt.log.Warningf("WebTransport stream accept failed: %v", err)
			sess.CloseWithError(0, "stream accept failed")
			return
		}
		conn := &webTransportConn{
			stream: stream,
			sess:   sess,
			local:  sess.LocalAddr(),
			remote: webTransportAddr(r.RemoteAddr),
		}
		wt.handleAcceptedStream(conn)
	})

	wt.Go(func() {
		wt.log.Noticef("Listening on WebTransport %s at %s", cfg.BindAddress, cfg.Path)
		if err := wt.server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile); err != nil && err != http.ErrServerClosed {
			wt.log.Errorf("WebTransport listener failed: %v", err)
		}
	})

	return wt, nil
}

func (l *webTransportListener) handleAcceptedStream(conn *webTransportConn) {
	var prefix [len(webTransportFrameMagic)]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		l.log.Warningf("WebTransport stream closed before protocol dispatch: %v", err)
		conn.Close()
		return
	}
	if string(prefix[:]) == webTransportFrameMagic {
		l.log.Debugf("Accepted new WebTransport control stream: %v", conn.RemoteAddr())
		if err := l.handleControlStream(conn, true); err != nil && !errors.Is(err, io.EOF) {
			l.log.Warningf("WebTransport control stream failed: %v", err)
		}
		conn.Close()
		return
	}

	l.log.Debugf("Accepted new WebTransport wire stream: %v", conn.RemoteAddr())
	l.onNewConn(&prefixedConn{Conn: conn, prefix: bytes.NewReader(prefix[:])})
}

func (l *webTransportListener) handleControlStream(conn net.Conn, consumedMagic bool) error {
	for {
		frame, err := readWebTransportControlFrame(conn, consumedMagic)
		consumedMagic = false
		if err != nil {
			return err
		}
		switch frame.typ {
		case webTransportFramePing:
			payload := append([]byte("katzenpost-wt-ok"), frame.payload...)
			if err := writeWebTransportControlFrame(conn, webTransportFramePong, webTransportStatusOK, payload); err != nil {
				return err
			}
		case webTransportFrameGetConsensus:
			if len(frame.payload) != 8 {
				if err := writeWebTransportControlFrame(conn, webTransportFrameConsensus, webTransportStatusError, nil); err != nil {
					return err
				}
				continue
			}
			epoch := binary.BigEndian.Uint64(frame.payload)
			rawDoc, err := l.glue.PKI().GetRawConsensus(epoch)
			status := webTransportStatusOK
			switch err {
			case nil:
			case cpki.ErrNoDocument:
				status = webTransportStatusNotFound
			case cpki.ErrDocumentGone:
				status = webTransportStatusGone
			default:
				status = webTransportStatusError
			}
			if status != webTransportStatusOK {
				rawDoc = nil
			}
			if err := writeWebTransportControlFrame(conn, webTransportFrameConsensus, status, rawDoc); err != nil {
				return err
			}
		case webTransportFrameSendPacket:
			if err := l.injectClientPacket(frame.payload); err != nil {
				l.log.Warningf("WebTransport packet injection failed: %v", err)
				if err := writeWebTransportControlFrame(conn, webTransportFramePacketAck, webTransportStatusError, []byte(err.Error())); err != nil {
					return err
				}
				continue
			}
			if err := writeWebTransportControlFrame(conn, webTransportFramePacketAck, webTransportStatusOK, []byte("accepted")); err != nil {
				return err
			}
		case webTransportFrameSendWithReply:
			if err := l.injectClientPacketAndWaitReply(conn, frame.payload); err != nil {
				l.log.Warningf("WebTransport packet injection with reply failed: %v", err)
				if err := writeWebTransportControlFrame(conn, webTransportFrameSurbReply, webTransportStatusError, []byte(err.Error())); err != nil {
					return err
				}
			}
		case webTransportFrameRegisterRecv:
			return l.registerWebTransportReceiver(conn, frame.payload)
		default:
			if err := writeWebTransportControlFrame(conn, frame.typ|0x80, webTransportStatusError, nil); err != nil {
				return err
			}
		}
	}
}

func (l *webTransportListener) injectClientPacket(raw []byte) error {
	pkt, err := packet.New(raw, l.glue.Config().SphinxGeometry)
	if err != nil {
		return err
	}
	pkt.MustForward = true
	pkt.RecvAt = time.Now()
	l.incomingCh <- pkt
	return nil
}

func (l *webTransportListener) injectClientPacketAndWaitReply(conn net.Conn, payload []byte) error {
	geo := l.glue.Config().SphinxGeometry
	expectedLen := sConstants.RecipientIDLength + geo.PacketLength
	if len(payload) != expectedLen {
		return fmt.Errorf("invalid send-with-reply payload size: %d, expected %d", len(payload), expectedLen)
	}

	var recipient [sConstants.RecipientIDLength]byte
	copy(recipient[:], payload[:sConstants.RecipientIDLength])
	rawPacket := payload[sConstants.RecipientIDLength:]

	replyCh := make(chan []byte, 1)
	l.glue.Gateway().RegisterWebTransportReplySession(recipient, replyCh)
	defer l.glue.Gateway().UnregisterWebTransportReplySession(recipient, replyCh)

	if err := l.injectClientPacket(rawPacket); err != nil {
		return err
	}

	select {
	case reply := <-replyCh:
		return writeWebTransportControlFrame(conn, webTransportFrameSurbReply, webTransportStatusOK, reply)
	case <-time.After(webTransportReplyWait):
		return writeWebTransportControlFrame(conn, webTransportFrameSurbReply, webTransportStatusNotFound, []byte("reply timeout"))
	}
}

func (l *webTransportListener) registerWebTransportReceiver(conn net.Conn, payload []byte) error {
	if len(payload) != sConstants.RecipientIDLength {
		return writeWebTransportControlFrame(conn, webTransportFrameRecvAck, webTransportStatusError, []byte("invalid receiver recipient size"))
	}

	var recipient [sConstants.RecipientIDLength]byte
	copy(recipient[:], payload)

	replyCh := make(chan []byte, 16)
	l.glue.Gateway().RegisterWebTransportReplySession(recipient, replyCh)
	defer l.glue.Gateway().UnregisterWebTransportReplySession(recipient, replyCh)

	if err := writeWebTransportControlFrame(conn, webTransportFrameRecvAck, webTransportStatusOK, []byte("registered")); err != nil {
		return err
	}

	var done <-chan struct{}
	if contextConn, ok := conn.(interface{ Context() context.Context }); ok {
		done = contextConn.Context().Done()
	}

	for {
		select {
		case reply := <-replyCh:
			if err := writeWebTransportControlFrame(conn, webTransportFrameSurbReply, webTransportStatusOK, reply); err != nil {
				return err
			}
		case <-done:
			return nil
		case <-l.HaltCh():
			return nil
		}
	}
}

type webTransportControlFrame struct {
	typ     byte
	status  uint16
	payload []byte
}

func readWebTransportControlFrame(r io.Reader, consumedMagic bool) (*webTransportControlFrame, error) {
	header := make([]byte, webTransportHeaderLen)
	if consumedMagic {
		copy(header, []byte(webTransportFrameMagic))
		if _, err := io.ReadFull(r, header[len(webTransportFrameMagic):]); err != nil {
			return nil, err
		}
	} else if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if string(header[:len(webTransportFrameMagic)]) != webTransportFrameMagic {
		return nil, errors.New("invalid WebTransport control frame magic")
	}
	if header[4] != webTransportVersion {
		return nil, fmt.Errorf("unsupported WebTransport control frame version %d", header[4])
	}
	payloadLen := binary.BigEndian.Uint32(header[8:12])
	if payloadLen > webTransportMaxPayload {
		return nil, fmt.Errorf("WebTransport control frame payload too large: %d", payloadLen)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &webTransportControlFrame{
		typ:     header[5],
		status:  binary.BigEndian.Uint16(header[6:8]),
		payload: payload,
	}, nil
}

func writeWebTransportControlFrame(w io.Writer, typ byte, status uint16, payload []byte) error {
	if len(payload) > webTransportMaxPayload {
		return fmt.Errorf("WebTransport control frame payload too large: %d", len(payload))
	}
	header := make([]byte, webTransportHeaderLen)
	copy(header, []byte(webTransportFrameMagic))
	header[4] = webTransportVersion
	header[5] = typ
	binary.BigEndian.PutUint16(header[6:8], status)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	if err := writeAll(w, header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
