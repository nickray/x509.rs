test:
	cargo test
	# check that "Subject:" line is `C = NZ, O = ACME, OU = Road Runner, CN = Test-in-a-Box`
	openssl x509 -in cert-names.der -inform DER -text -noout
	diff cert-names.der cert-names.der.expected
	# check that "X509v3 extensions:" line contains non-critical 1.2.3.4 and critical 1.4.5.6
	openssl x509 -in cert-extensions.der -inform DER -text -noout
	diff cert-extensions.der cert-extensions.der.expected
