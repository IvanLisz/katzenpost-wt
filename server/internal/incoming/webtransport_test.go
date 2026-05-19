package incoming

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type bufferConn struct {
	bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) LocalAddr() net.Addr              { return nil }
func (c *bufferConn) RemoteAddr() net.Addr             { return nil }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

func TestWebTransportControlFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("dummy")
	require.NoError(t, writeWebTransportControlFrame(&buf, webTransportFramePing, webTransportStatusOK, payload))

	frame, err := readWebTransportControlFrame(&buf, false)
	require.NoError(t, err)
	require.Equal(t, byte(webTransportFramePing), frame.typ)
	require.Equal(t, webTransportStatusOK, frame.status)
	require.Equal(t, payload, frame.payload)
}

func TestWebTransportControlFrameConsumedMagic(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeWebTransportControlFrame(&buf, webTransportFrameGetConsensus, 0, make([]byte, 8)))

	magic := make([]byte, len(webTransportFrameMagic))
	_, err := io.ReadFull(&buf, magic)
	require.NoError(t, err)
	require.Equal(t, webTransportFrameMagic, string(magic))

	frame, err := readWebTransportControlFrame(&buf, true)
	require.NoError(t, err)
	require.Equal(t, byte(webTransportFrameGetConsensus), frame.typ)
	require.Len(t, frame.payload, 8)
}

func TestWebTransportControlFrameRejectsBadMagic(t *testing.T) {
	buf := bytes.NewBuffer([]byte("NOPE\x01\x01\x00\x00\x00\x00\x00\x00"))
	_, err := readWebTransportControlFrame(buf, false)
	require.Error(t, err)
}

func TestWebTransportReceiverRejectsInvalidRecipientLength(t *testing.T) {
	conn := new(bufferConn)
	listener := new(webTransportListener)

	require.NoError(t, listener.registerWebTransportReceiver(conn, []byte("short")))

	frame, err := readWebTransportControlFrame(&conn.Buffer, false)
	require.NoError(t, err)
	require.Equal(t, byte(webTransportFrameRecvAck), frame.typ)
	require.Equal(t, webTransportStatusError, frame.status)
	require.Contains(t, string(frame.payload), "invalid receiver recipient size")
}
