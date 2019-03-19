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

        key = x509der.public_key
        if OpenSSL::X509::Certificate == x509der
          key = key.public_key
        end
        bx = key.to_bn
        grp= key.group
        point = ECDSA::Format::PointOctetString.decode_from_ssl(bx, grp)
        #puts "PUBKEY DECODED TO: #{point.x.to_s},#{point.y.to_s}"
        point
      end
    end

    module PrivateKey
      def self.decode(x509privkey)
        bx = x509privkey.private_key
        grp = ECDSA::Group.group_from_openssl(x509privkey.group)
        return [ECDSA::Format::IntegerOctetString.decode_priv_from_ssl(bx, x509privkey.group), grp]
      end
    end
  end
end
