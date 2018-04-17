require 'openssl'
require_relative '../signature'

module ECDSA
  module Format
    # This module provides methods to convert between Public and Private
    # keys in ECDSA format, and ASN.1 format.
    module PubKey
      # Converts an (OpenSSL) X509 format ECDSA public key into one that
      # this module can use.
      def self.decode(x509der)
        bx = x509der.public_key.public_key.to_bn
        grp= x509der.public_key.public_key.group
        point = ECDSA::Format::PointOctetString.decode_from_ssl(bx, grp)
      end
    end

    module PrivateKey
      def self.decode(x509privkey)
        bx = x509privkey.private_key
        grp= x509privkey.group
        ECDSA::Format::PointOctetString.decode_priv_from_ssl(bx, grp)
      end
    end
  end
end
