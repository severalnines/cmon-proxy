package rpcserver
// Copyright 2022 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.


import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// CreateTLSCertificate creates a self-signed key/cert pair for https server
// you can give the destination path without extension (.crt/.key will be added),
// and optionally pass hostnames to be written to the cert
func CreateTLSCertificate(certPath, keyPath string, hostnames ...string) (err error) {
	var privateKey *ecdsa.PrivateKey
	var certFile, keyFile *os.File
	var derBytes, keyBytes []byte

	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	// generate a random serial number
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if serialNumber == nil || serialNumber.Sign() <= 0 {
		serialNumber = big.NewInt(123456)
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Severalnines AB"},
		},
		NotBefore:             time.Now().Add(time.Hour * time.Duration(-24)),
		NotAfter:              time.Now().Add(time.Hour * time.Duration(24*365*10)),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}

	if derBytes, err = x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey); err != nil {
		return
	}

	// save the PEM encoded certificate
	certFile, err = os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	defer certFile.Close()
	if err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return
	}

	// and save the PEM encoded private key in PKCS8 format
	keyFile, err = os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer keyFile.Close()
	if keyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
		return
	}

	err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return
}
