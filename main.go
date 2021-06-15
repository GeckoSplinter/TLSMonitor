package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"gopkg.in/yaml.v2"
)

type Config struct {
	PromUrl     string   `yaml:"prometheus_url"`
	NbDialRetry int      `yaml:"nb_dial_retry"`
	Hosts       []string `yaml:"hosts,omitempty"`
	CertsPaths  []string `yaml:"certs_paths,omitempty"`
}

var (
	config = flag.String("config", "config.yaml", "Path to config file")
	debug  = flag.Bool("debug", false, "Enable debug logs")
)

var (
	hostCertExpirationDate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "host_cert_expiration_date",
			Help: "The expiration date in sec of the host cert",
		},
		[]string{"target", "ip", "certAuthority"},
	)
	fileCertExpirationDate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "file_cert_expiration_date",
			Help: "The expiration date in sec of the file cert",
		},
		[]string{"filename", "cn", "dnsNames", "certAuthority"},
	)
)

func InitMetrics() {
	prometheus.MustRegister(hostCertExpirationDate)
	prometheus.MustRegister(fileCertExpirationDate)
}

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

func checkFileCert(certPath string, config *Config) {
	f, errReadFile := ioutil.ReadFile(certPath)
	if errReadFile != nil {
		log.WithFields(log.Fields{"certPath": certPath}).Error(errReadFile.Error())
		return
	}
	pem, _ := pem.Decode(f)
	if pem == nil {
		log.WithFields(log.Fields{"certPath": certPath}).Error("Error decoding pem: ", certPath)
		return
	}
	certs, err := x509.ParseCertificates(pem.Bytes)
	if err != nil {
		log.WithFields(log.Fields{"certPath": certPath}).Error(err.Error())
		return
	}
	log.WithFields(log.Fields{"cn": certs[0].Subject.CommonName, "date": certs[0].NotAfter}).Info("Checking certificate: ", certs[0].Subject.CommonName)

	if config.PromUrl != "" {
		fileCertExpirationDate.WithLabelValues(certPath, certs[0].Subject.CommonName, strings.Join(certs[0].DNSNames, ", "), certs[0].Issuer.CommonName).Set(float64(certs[0].NotAfter.Unix()))
		errPushProm := retry(config.NbDialRetry, 5*time.Second, func() (err error) {
			err = push.New(config.PromUrl, "tlsmonitor-files").Collector(fileCertExpirationDate).Push()
			return
		})
		if errPushProm != nil {
			log.Error("Could not push completion time to Pushgateway: ", errPushProm)
		}
	}
}

func checkHostCert(target string, config *Config) {
	targetPort := strings.Split(target, ":")
	port := "443"
	host := targetPort[0]
	if len(targetPort) > 2 {
		log.WithFields(log.Fields{"host": target}).Error("Host value not valid")
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
		log.WithFields(log.Fields{"host": host}).Error("Lookup IP failed")
		pushHostCert(host, "0.0.0.0", "NA", -1, config)
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
				log.WithFields(log.Fields{"status": "FAILED", "host": host, "ip": ip}).Warn(errDial.Error())
				pushHostCert(host, ip.String(), "NA", -2, config)
				return
			}
			defer conn.Close()
			// Certificate is first in chain
			endCert := conn.ConnectionState().PeerCertificates[0]
			if timeNow.After(endCert.NotAfter) {
				log.WithFields(log.Fields{"status": "EXPIRED", "host": host, "ip": ip, "date": endCert.NotAfter}).Warn("Cert is expired: ", endCert.Subject.CommonName)
			} else if timeNow.AddDate(alertYears, alertMonths, alertDays).After(endCert.NotAfter) {
				durationDays := int(-timeNow.Sub(endCert.NotAfter).Hours()) / 24
				log.WithFields(log.Fields{"status": "SOON", "host": host, "ip": ip, "remaining": durationDays, "date": endCert.NotAfter}).Warn("Cert will expired soon: ", endCert.Subject.CommonName)
			} else {
				log.WithFields(log.Fields{"status": "VALID", "host": host, "ip": ip, "date": endCert.NotAfter}).Info("Cert is valid: ", endCert.Subject.CommonName)
			}
			pushHostCert(host, ip.String(), endCert.Issuer.CommonName, float64(endCert.NotAfter.Unix()), config)
		}
	}
}

func pushHostCert(host string, ip string, ca string, value float64, config *Config) {
	if config.PromUrl == "" {
		return
	}
	// metrics.WithLabelValues(labels...).Set(value) generic version
	hostCertExpirationDate.WithLabelValues(host, ip, ca).Set(value)
	errPushProm := retry(config.NbDialRetry, 5*time.Second, func() (err error) {
		err = push.New(config.PromUrl, "tlsmonitor-hosts").Collector(hostCertExpirationDate).Push()
		return
	})
	if errPushProm != nil {
		log.Error("Could not push completion time to Pushgateway: ", errPushProm)
	}
}

func main() {
	flag.Parse()

	Formatter := new(log.TextFormatter)
	Formatter.TimestampFormat = "02-01-2006 15:04:05"
	Formatter.FullTimestamp = true
	log.SetFormatter(Formatter)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	yamlFile, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	config := Config{}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatal(err.Error())
	}
	InitMetrics()

	if config.NbDialRetry == 0 {
		config.NbDialRetry = 3
	}

	var wgHosts sync.WaitGroup
	wgHosts.Add(len(config.Hosts))
	for _, host := range config.Hosts {
		go func(host string) {
			checkHostCert(host, &config)
			wgHosts.Done()
		}(host)
	}

	for _, certPath := range config.CertsPaths {
		fm, err := os.Stat(certPath)
		if err != nil {
			log.WithFields(log.Fields{"certPath": certPath}).Error(err.Error())
			continue
		}
		if fm.Mode().IsRegular() {
			go func(certPath string) {
				checkFileCert(certPath, &config)
			}(certPath)
		} else if fm.Mode().IsDir() {
			var files []string
			err := filepath.Walk(certPath, func(path string, info os.FileInfo, err error) error {
				if info.IsDir() {
					return nil
				} else if strings.Contains(info.Name(), "key") {
					log.Debug("Cert checking excluded key file: ", info.Name())
					return nil
				}
				files = append(files, path)
				log.Debug("Cert checking add ", info.Name(), " to list of certs")
				return nil
			})
			if err != nil {
				log.Error(err.Error())
				continue
			}
			for _, file := range files {
				checkFileCert(file, &config)
			}
		}
	}
	wgHosts.Wait()
}
