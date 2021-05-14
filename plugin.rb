# frozen_string_literal: true

# name: discourse_sso_override
# about: Plugin to override SSO parse method for DesignBundle SSO logic flow
# version: 1.0
# author: Edward Skalibog (@skalibog)
# url: https://github.com/gotoinc/discourse_sso

ACCESSORS = %i{
    add_groups
    admin moderator
    avatar_force_update
    avatar_url
    bio
    card_background_url
    email
    external_id
    groups
    locale
    locale_force_update
    logout
    name
    nonce
    profile_background_url
    remove_groups
    require_activation
    return_sso_url
    suppress_welcome_message
    title
    username
    website
    location
  }

FIXNUMS = []

BOOLS = %i{
    admin
    avatar_force_update
    locale_force_update
    logout
    moderator
    require_activation
    suppress_welcome_message
  }


after_initialize do
  SingleSignOn.class_eval do
    def self.parse(payload, sso_secret = nil)
      sso = new
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
