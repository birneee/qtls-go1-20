package qtls

import "net"

func CipherSuiteTLS13ByID(id uint16) *CipherSuiteTLS13 {
	return cipherSuiteTLS13ByID(id)
}

// FromTrafficSecret creates a new TLS connection without doing a handshake
// only accepts TLS 1.3 cipher suites
func FromTrafficSecret(conn net.Conn, cipherSuiteId uint16, rcvTrafficSecret []byte, sendTrafficSecret []byte, config *Config, extraConfig *ExtraConfig, isClient bool) *Conn {
	c := &Conn{
		conn:        conn,
		config:      fromConfig(config),
		extraConfig: extraConfig,
		isClient:    isClient,
	}
	c.isHandshakeComplete.Store(true)
	c.haveVers = true
	c.vers = VersionTLS13
	c.cipherSuite = cipherSuiteId
	suite := cipherSuiteTLS13ByID(cipherSuiteId)
	c.in.setTrafficSecret(suite, QUICEncryptionLevelApplication, rcvTrafficSecret)
	c.in.version = VersionTLS13
	c.out.setTrafficSecret(suite, QUICEncryptionLevelApplication, sendTrafficSecret)
	c.out.version = VersionTLS13
	return c
}
