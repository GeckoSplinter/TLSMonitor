package tls

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
	"tlsmonitor/pkg/config"
	"tlsmonitor/pkg/metrics"

	log "github.com/sirupsen/logrus"
)

func retry(attempts int, sleep time.Duration, f func() error) (err error) {
	for i := 0; ; i++ {
		err = f()
		if err == nil {
			return
		}
		if i >= (attempts - 1) {
			break
		}
		time.Sleep(sleep)
		log.WithFields(log.Fields{"retry_count": i}).Debug("Retrying after error:", err)
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}

func CheckHostCert(target string, config *config.Config) {
	log.WithFields(log.Fields{"fqdn": target}).Info("Checking cert")
	targetPort := strings.Split(target, ":")
	port := "443"
	host := targetPort[0]
	if len(targetPort) > 2 {
		log.WithFields(log.Fields{"fqdn": target}).Error("Host value not valid")
		return
	} else if len(targetPort) == 2 {
		port = targetPort[1]
	}

	// Set to insecure because of internal PKI certiticates or self signed wrong hosts ...
	dialConfig := tls.Config{ServerName: host, InsecureSkipVerify: true}

	var ips []net.IP
	errLookup := retry(config.NbDialRetry, 5*time.Second, func() (err error) {
		ips, err = net.LookupIP(host)
		return
	})
	if errLookup != nil {
		log.WithFields(log.Fields{"fqdn": host}).Error("Lookup IP failed")
		//pushHostCert(host, "0.0.0.0", "NA", -1, config)
		if config.Metrics.Enabled {
			metrics.UpdateHostCert(host, "0.0.0.0", "NA", -1)
		}
		return
	}

	timeNow := time.Now()
	alertYears := 0
	alertMonths := 0
	alertDays := 40

	for _, ip := range ips {
		if ip.To4() != nil {
			var conn *tls.Conn
			errDial := retry(config.NbDialRetry, 5*time.Second, func() (err error) {
				conn, err = tls.Dial("tcp", fmt.Sprint(ip, ":", port), &dialConfig)
				return
			})
			if errDial != nil {
				log.WithFields(log.Fields{"status": "FAILED", "fqdn": host, "ip": ip}).Warn(errDial.Error())
				//pushHostCert(host, ip.String(), "NA", -2, config)
				if config.Metrics.Enabled {
					metrics.UpdateHostCert(host, ip.String(), "NA", -2)
				}
				return
			}
			defer conn.Close()
			// Certificate is first in chain
			endCert := conn.ConnectionState().PeerCertificates[0]
			if timeNow.After(endCert.NotAfter) {
				log.WithFields(log.Fields{"status": "EXPIRED", "fqdn": host, "ip": ip, "expiration": endCert.NotAfter}).Warn("Cert is expired: ", endCert.Subject.CommonName)
			} else if timeNow.AddDate(alertYears, alertMonths, alertDays).After(endCert.NotAfter) {
				durationDays := int(-timeNow.Sub(endCert.NotAfter).Hours()) / 24
				log.WithFields(log.Fields{"status": "SOON", "fqdn": host, "ip": ip, "remaining": durationDays, "expiration": endCert.NotAfter}).Warn("Cert will expired soon: ", endCert.Subject.CommonName)
			} else {
				log.WithFields(log.Fields{"status": "VALID", "fqdn": host, "ip": ip, "expiration": endCert.NotAfter}).Info("Cert is valid: ", endCert.Subject.CommonName)
			}
			//pushHostCert(host, ip.String(), endCert.Issuer.CommonName, float64(endCert.NotAfter.Unix()), config)
			if config.Metrics.Enabled {
				metrics.UpdateHostCert(host, ip.String(), endCert.Issuer.CommonName, float64(endCert.NotAfter.Unix()))
			}
		}
	}
}
