# frozen_string_literal: true

# name: discourse_sso_override
# about: Plugin to override SSO parse method for DesignBundle SSO logic flow
# version: 1.0
# author: Edward Skalibog (@skalibog)
# url: https://github.com/gotoinc/discourse_sso

after_initialize do
  SingleSignOn.class_eval do
    class << self
      alias_method :original_parse, :parse
    end

    def self.parse(payload, sso_secret = nil, **init_kwargs)
      sso = new(**init_kwargs)
      sso.sso_secret = sso_secret if sso_secret

      parsed = Rack::Utils.parse_query(payload)
      decoded = Base64.decode64(parsed["sso"])
      decoded_hash = Rack::Utils.parse_query(decoded)

      if sso.sign(parsed["sso"]) != parsed["sig"]
        diags = "\n\nsso: #{parsed["sso"]}\n\nsig: #{parsed["sig"]}\n\nexpected sig: #{sso.sign(parsed["sso"])}"
        if parsed["sso"] =~ /[^a-zA-Z0-9=\r\n\/+]/m
          raise ParseError, "The SSO field should be Base64 encoded, using only A-Z, a-z, 0-9, +, /, and = characters. Your input contains characters we don't understand as Base64, see http://en.wikipedia.org/wiki/Base64 #{diags}"
        else
          raise ParseError, "Bad signature for payload #{diags}"
        end
      end

      ACCESSORS.each do |k|
        val = decoded_hash[k.to_s]
        val = val.to_i if FIXNUMS.include? k
        if BOOLS.include? k
          val = ["true", "false"].include?(val) ? val == "true" : nil
        end

        if %w(admin moderator).include?(k.to_s)
          sso.public_send("#{k}=", val) if val
        else
          sso.public_send("#{k}=", val)
        end
      end

      decoded_hash.each do |k, v|
        if field = k[/^custom\.(.+)$/, 1]
          sso.custom_fields[field] = v
        end
      end

      sso
    end
  end
end
