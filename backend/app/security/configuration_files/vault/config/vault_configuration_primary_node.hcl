# /vault/config/config.hcl  (Leader: Node 1)

listener "tcp" {
  address                  = "0.0.0.0:8200"
  cluster_address          = "0.0.0.0:8201"
  tls_disable              = 0                          # use 1 only for testing
  tls_cert_file            = "/vault/certs/cert.crt"    # cert
  tls_key_file             = "/vault/certs/cert.key"
  tls_disable_client_certs = true
}

storage "raft" {
  path    = "/vault/data"
  node_id = "Node1"
}

ui = true