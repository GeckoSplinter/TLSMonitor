package metrics

import (
	"fmt"
	"net/http"
	"tlsmonitor/pkg/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func UpdateHostCert(host string, ip string, ca string, value float64) {
	hostCertExpirationDate.WithLabelValues(host, ip, ca).Set(value)
}

func UpdateFileCert(filename string, cn string, dnsNames string, certAuthority string, value float64) {
	fileCertExpirationDate.WithLabelValues(filename, cn, dnsNames, certAuthority).Set(value)
}

func InitMetrics() {
	prometheus.MustRegister(hostCertExpirationDate)
	prometheus.MustRegister(fileCertExpirationDate)
}

func ServeMetrics(config config.Metrics) {

	http.Handle(config.Path, promhttp.Handler())
	http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil)
}
