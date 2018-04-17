# encoding: ASCII-8BIT

require_relative '../point'

module ECDSA
  module Format
    # This module provides methods for converting between {Point} objects and "octet strings",
    # which are just strings with binary data in them that have the coordinates of the point.
    # The point octet string format is defined in two sections of [SEC1](http://www.secg.org/collateral/sec1_final.pdf):
    #
    # * Section 2.3.3: EllipticCurvePoint-to-OctetString Conversion
    # * Section 2.3.4: OctetString-to-EllipticCurvePoint Conversion
    module PointOctetString
      # Converts a {Point} to an octet string.
      #
      # @param point (Point)
      # @param opts (Hash)
      # @option opts :compression Set this option to true to generate a compressed
      #   octet string, which only has one bit of the Y coordinate.
      #   (Default: false)
      def self.encode(point, opts = {})
        return "\x00" if point.infinity?

        if opts[:compression]
          start_byte = point.y.even? ? "\x02" : "\x03"
          start_byte + FieldElementOctetString.encode(point.x, point.group.field)
        else
          "\x04" +
            FieldElementOctetString.encode(point.x, point.group.field) +
            FieldElementOctetString.encode(point.y, point.group.field)
        end
      end

      def self.decode_from_ssl(ecpoint, group)
        grp = ECDSA::Group.group_from_openssl(group)
        size = ecpoint.num_bytes
        bytes = Array.new(size)
        (1..size).each {
          size -= 1
          bytes[size] = (ecpoint % 256).to_i;
          ecpoint = ecpoint >> 8;
        }
        return decode_array(bytes, grp)
      end

      # Converts an octet string to a {Point} in the specified group.
      # Raises a {DecodeError} if the string is invalid for any reason.
      #
      # This is equivalent to
      # [ec_GFp_simple_oct2point](https://github.com/openssl/openssl/blob/a898936/crypto/ec/ecp_oct.c#L325)
      # in OpenSSL.
      #
      # @param string (String)
      # @param group (Group)
      # @return (Point)
      def self.decode(string, group)
        string = string.dup.force_encoding('BINARY')
        return decode_array(string, group)
      end

      def self.decode_array(array, group)
        raise DecodeError, 'Point octet string is empty.' if array.empty?

        case array[0].ord
        when 0
          check_length array, 1
          return group.infinity
        when 2
          decode_compressed array, group, 0
        when 3
          decode_compressed array, group, 1
        when 4
          decode_uncompressed array, group
        else
          raise DecodeError, 'Unrecognized start byte for point octet array: 0x%x' % array[0].ord
        end
      end

      def self.decode_from_integer(bignum_x, group, y_lsb)
        possible_ys = group.solve_for_y(x)
        y = possible_ys.find { |py| (py % 2) == y_lsb }
        raise DecodeError, 'Could not solve for y.' if y.nil?

        finish_decode x, y, group
      end

      private

      def self.decode_compressed(string, group, y_lsb)
        expected_length = 1 + group.byte_length
        check_length string, expected_length

        x_string = string[1, group.byte_length]
        x = ECDSA::Format::FieldElementOctetString.decode x_string, group.field

        decode_from_integer(x, group, y_lsb)
      end

      def self.decode_uncompressed(string, group)
        expected_length = 1 + 2 * group.byte_length
        check_length string, expected_length

        x_string = string[1, group.byte_length]
        y_string = string[1 + group.byte_length, group.byte_length]
        x = ECDSA::Format::FieldElementOctetString.decode x_string, group.field
        y = ECDSA::Format::FieldElementOctetString.decode y_string, group.field

        finish_decode x, y, group
      end

      def self.finish_decode(x, y, group)
        point = group.new_point [x, y]
        if !group.include? point
          raise DecodeError, "Decoded point does not satisfy curve equation: #{point.inspect}."
        end
        point
      end

      def self.check_length(string, expected_length)
        if string.length != expected_length
          raise DecodeError, "Expected point octet string to be length #{expected_length} but it was #{string.length}."
        end
      end
    end
  end
end
