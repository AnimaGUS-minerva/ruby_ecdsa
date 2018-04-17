module ECDSA
  module Format
    # This module provides methods for converting integers to big endian octet
    # strings.  The conversions are defined in these sections of
    # [SEC1](http://www.secg.org/collateral/sec1_final.pdf):
    #
    # * Section 2.3.7: Integer-to-OctetString Conversion
    # * Section 2.3.8: OctetString-to-Integer Conversion
    #
    # We use Ruby integers to represent bit strings, so this module can also be
    # thought of as implementing these sections of SEC1:
    #
    # * Section 2.3.1: BitString-to-OctetString Conversion
    # * Section 2.3.2: OctetString-to-BitString Conversion
    module IntegerOctetString
      # @param integer (Integer) The integer to encode.
      # @param length (Integer) The number of bytes desired in the output string.
      # @return (String)
      def self.encode(integer, length)
        raise ArgumentError, 'Integer to encode is negative.' if integer < 0
        raise ArgumentError, 'Integer to encode is too large.' if integer >= (1 << (8 * length))

        (length - 1).downto(0).map do |i|
          (integer >> (8 * i)) & 0xFF
        end.pack('C*')
      end

      def self.decode_priv_from_ssl(ecpoint, group)
        grp = ECDSA::Group.group_from_openssl(group)
        size = ecpoint.num_bytes
        bytes = Array.new(size)
        (1..size).each {
          size -= 1
          bytes[size] = (ecpoint % 256).to_i;
          ecpoint = ecpoint >> 8;
        }
        ECDSA::Format::FieldElementOctetString.decode bytes, grp.field
      end

      # @param string (String)
      # @return (Integer)
      def self.decode(string)
        case string
        when String
          string = string.bytes
        end
        string.reduce { |n, b| (n << 8) + b }
      end
    end
  end
end
