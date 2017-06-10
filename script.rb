#!/usr/bin/env ruby

require 'pp'
require 'cryptopp'

module ABNF
  IANAToken    = '[a-zA-Z\d\-]+?'
  Cr           = "\u000d"
  Lf           = "\u000a"
  Crlf         = "(#{Cr}|#{Lf})"
  Utf8_tail    = '[\u0080-\u00bf]'
  Utf8_2       = '([\u00c2-\u00df]|' + "#{Utf8_tail})"
  Utf8_3       = '([\u00e0\u00a0-\u00bf\u00e1-\u00ec\u00ed\u0080-\u009f\u00ee-\u00ef]|' + "#{Utf8_tail})"
  Utf8_4       = '([\u00f0\u0090-\u00bf\u00f1-\u00f3\u00f4\u0080-\u008f]|' + "#{Utf8_tail})"
  Wsp          = '[ \t]'
  VChar        = '[\u0021-\u007e]'
  NonASCII     = "(#{Utf8_2}|#{Utf8_3}|#{Utf8_4})"
  QSafeChar    = "(#{Wsp}|" + '[!\u0023-\u007e]' + "|#{NonASCII})"
  SafeChar     = "(#{Wsp}|" + '[!\u0023-\u0039\u003c-\u007e]' + "|#{NonASCII})"
  ValueChar    = "(#{Wsp}|#{VChar}|#{NonASCII})"
  DQuote       = '"'
  PText        = "#{SafeChar}*?"
  QuotedString = "#{DQuote}(#{QSafeChar}*?)#{DQuote}"
  XName        = "[xX]-#{IANAToken}"
  Group        = IANAToken
  Name         = "(#{XName}|#{IANAToken})"
  ParamName    = "(#{XName}|#{IANAToken})"
  ParamValue   = "(#{PText}|#{QuotedString})"
  PValueList   = "(?<head>#{ParamValue})(?<tail>(,#{ParamValue})*)"
  Pid          = '\d+(\.\d+)*'
  PidList      = "(?<head>#{Pid})(?<tail>(,#{Pid})*)"
  Param        = "(?<pname>#{ParamName})=(?<pvalue>#{PValueList})"
  Params       = "(;(?<phead>#{Param}))(?<ptail>(;#{Param})*)"
  Value        = "#{ValueChar}*?"
  LineGroup    = "((?<group>#{Group})" + '\.' + ")?"
  Contentline  = "#{LineGroup}(?<key>#{Name})(?<params>(#{Params})?):(?<value>#{Value})#{Crlf}"
  BeginLine    = "BEGIN:(?<component>#{VChar}+)#{Crlf}"
  EndLine      = "END:#{VChar}+#{Crlf}"
  VersionLine  = "VERSION:(?<version>#{VChar}+)#{Crlf}"
  Vcard        = "#{BeginLine}#{VersionLine}(#{Contentline})+#{EndLine}"

  Component    = "#{BeginLine}(?<body>.*)#{EndLine}"

  ComponentRegex = /\A#{ABNF::Component}\Z/m
  VcardRegex   = /\A#{ABNF::Vcard}\Z/
  ContentlineRegex   = /\A#{ABNF::Contentline}\Z/
  ParamsRegex   = /\A#{ABNF::Params}\Z/
  ParamRegex   = /\A#{ABNF::Param}\Z/

end


class Component
  attr_accessor :name, :body, :properties

  def initialize(string)
    matched = ABNF::ComponentRegex.match(string)
    @name = matched[:component]
    @body = matched[:body]
  end

  def parse_properties
    @properties = []
    # TODO: simplistic splitting
    @body.each_line do |line|
      @properties << ComponentProperty.new(line)
    end
  end

  def to_hash_string
"BEGIN:#{@name}:CHECKSUM
#{properties_to_hash_string}
END:#{@name}:CHECKSUM"
  end

  def properties_to_hash_string
    list_to_text(
      @properties.map do |prop|
        prop.normalized_hash
      end.sort,
      "\r\n"
    )
  end

  def hash
    calculate_hash to_hash_string
  end
end

class ComponentProperty
  attr_accessor :key, :value, :params, :value_type

  def initialize(string)
    raise ArgumentError.new("No input string provided") unless string

    matched = ABNF::ContentlineRegex.match(string)
    pp string

    #puts "ComponentProperty: string #{string}"
    #puts "ComponentProperty: matched #{matched.inspect}"
#     pp "matched are"
#     pp matched
    @key = matched[:key].upcase
    @value = matched[:value]
    @params = {}

    case @key
    when "ADR", "N"
      @value = @value.split(";")
    when "CATEGORY", "NICKNAME"
      @value = @value.split(",")
    else
      @value = [@value]
    end

    params = matched[:params]

    # Simplistic assumption: by default VALUE=TEXT
    value_type = PropertyParameter.new("VALUE=TEXT")
    @params[value_type.name] = value_type

    # TODO: simplistic splitting of params
    params.split(";").each do |param|
      #puts "params is #{param}"
      next if param.empty?
      param = PropertyParameter.new(param)
      pk = param.name
      @params[pk] = param
    end

    @value_type = @params["VALUE"].value.first
    @params.delete("VALUE")
  end

  def hash
    calculate_hash to_hash_string
  end

  def normalized_hash
    "#{@key}:#{hash}"
  end

  def to_hash_string
    "#{@key}:#{@value_type}/" +
    (@value.is_a?(Array) ? list_to_text(@value, ";") : @value) +
    "?#{sorted_parameters_to_hash_string}"
  end

  def sorted_parameters
    @params.sort_by do |key, obj|
      key
    end.map do |arr|
      arr.last
    end
  end

  def sorted_parameters_to_hash_string
    param_string = sorted_parameters.map do |param|
      param.to_hash_string
    end

    "##{list_to_text(param_string, ";")}"
  end

end

# class PropertyParameters
#
#   attr_accessor :mapping
#
#   def initialize(string)
#     matched = ABNF::ParamsRegex.match(string)
#     puts "PropertyParameter: string #{string}"
#
#     @key = matched[:key]
#     @value = matched[:value]
#
#   end
# end

class PropertyParameter
  attr_accessor :name, :value
  def initialize(string)
    raise ArgumentError.new("No input string provided") unless string

    matched = ABNF::ParamRegex.match(string)
    #puts "PropertyParameter: string #{string}"
    #puts "PropertyParameter: matched #{matched.inspect}"
    @name = matched[:pname].upcase

    # TODO: simplistic splitting
    @value = matched[:pvalue]
    if valuematch = /\A"(.*)"\Z/.match(@value)
      @value = valuematch[1]
    end

    # Upcase the property value type
    if @name == "VALUE"
      @value = [@value.upcase]
    else
      @value = @value.split(",")
    end
  end

  def to_hash_string
    "{#{@name}:#{list_to_text(@value.sort, ";")}}"
  end
end


def calculate_hash(s, alg = HASH_FUNCTION_NAME)
  calculate_hash_cryptopp(s, alg)
end

def calculate_hash_cryptopp(s, alg)

  cryptopp_alg = case alg
  when :sha256, :sha384, :sha512
    alg
  when :sha512224
  when :sha512256
  when :sha3224
    :sha3_224
  when :sha3256
    :sha3_256
  when :sha3384
    :sha3_384
  when :sha3512
    :sha3_512
  when :blake2b
    alg
  when :whirlpool
    alg
  when :streebog512
  when :streebog256
  when :ripemd256, :ripemd320
    alg
  when :sm3
  end

  unless CryptoPP.digest_enabled? cryptopp_alg
    raise ArgumentError.new("No hash function #{cryptopp_alg} available")
  end

  CryptoPP.digest_factory(cryptopp_alg, s)
end

#require 'digest'
#require 'sha3-pure-ruby'
#require 'digest/whirlpool'
def calculate_hash_original(s, alg)
  klass = case alg
  when :sha256
    Digest::SHA256
  when :sha384
    Digest::SHA384
  when :sha512
    Digest::SHA512
  when :sha3224
    Digest::SHA3.new(224)
  when :sha3384
    Digest::SHA3.new(384)
  when :sha3512
    Digest::SHA3.new(512)
  when :whirlpool
    # Currently fails
    Digest::Whirlpool
  end

  klass.hexdigest s
end

def list_to_text(array, delimiter)
  "#{array.join(delimiter || "")}"
end



data = 'BEGIN:VCARD
VERSION:4.0
KIND:individual
FN:Martin Van Buren
N:Van Buren;Martin;;;Hon.
TEL;VALUE=uri;PREF=1;TYPE="voice,home":tel:+1-888-888-8888;ext=8888
CHECKSUM;VALUE=TEXT;TYPE=sha512:
END:VCARD
'

# Choose your hash function here
HASH_FUNCTION_NAME = :whirlpool
HASH_FUNCTION_NAME = :ripemd256
HASH_FUNCTION_NAME = :blake2b
HASH_FUNCTION_NAME = :sha3256


component = Component.new(data)

#pp component.body
component.parse_properties

#pp component
#pp component.properties
component.properties.map do |prop|
  #pp prop.params
  #pp prop.value_type
  puts "1. Hash string for property #{prop.key}"
  puts prop.to_hash_string
end

component.properties.map do |prop|
  puts "2. Normalized hash for property #{prop.key}"
  puts prop.normalized_hash
end

puts "3. Component hash string is:"
puts component.to_hash_string

puts "4. Component hash is:"
puts component.hash

