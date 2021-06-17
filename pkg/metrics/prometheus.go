package metrics

import (
	"net/http"

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

func updateHostCert(host string, ip string, ca string, value float64) {
	hostCertExpirationDate.WithLabelValues(host, ip, ca).Set(value)
}

func main() {
	prometheus.MustRegister(hostCertExpirationDate)
	prometheus.MustRegister(fileCertExpirationDate)

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}

func ServeMetrics(metricsConfig config) {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9090", nil)
}
