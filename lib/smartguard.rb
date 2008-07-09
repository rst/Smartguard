#--
# Copyright (c) 2008 Robert S. Thau, Smartleaf, Inc.
# 
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

require 'digest/sha2'

module Smartguard

  class Logging

    @hooks = []

    def self.add_hook( &block )
      @hooks << block
    end

    def self.log( log_info )
      @hooks.each{ |hook| hook.call( log_info ) }
    end

  end

  module Utils

    def self.random_chars

      # Hash a bunch of stuff, all hopefully adding entropy
      # (including /dev/urandom or /dev/random if we have them).
      # May be overkill for some applications, but better safe
      # than sorry.

      raw_string = rand.to_s
      [ :pid, :ppid, :uid, :gid ].each do |msg| 
        raw_string += '.' + Process.send( msg ).to_s
      end
      tm = Time.now
      raw_string += '.' + tm.to_s
      raw_string += '.' + tm.usec.to_s
      raw_string += '.' + rand.to_s

      if File.readable?('/dev/urandom')
        begin
          File.open('/dev/urandom') do |f|
            raw_string += f.read(8)
          end
        rescue Exception
        end
      end

      return Base64.encode64( Digest::SHA256.digest( raw_string ))

    end

  end

  module Bootstrap

    def self.boot_key( param_name )
      'boot_' + param_name.to_s
    end

    def self.boot_param( param_name )
      ENV[ boot_key( param_name ) ]
    end

    def self.default_boot_param( param_name )

      stored_val = boot_param( param_name )
      return stored_val unless stored_val.nil?

      default_val = yield

      if default_val.nil?
        raise InternalError, 
          "Could not default bootstrap parameter #{param_name}"
      else
        puts "Defaulting bootstrap #{param_name} to '#{default_val}'"
      end

      ENV[ boot_key( param_name ) ] = default_val
      return default_val

    end

    def self.current_pwuid
      Etc.getpwuid( Process.uid )
    end

    def self.initial_login
      self.default_boot_param( 'login' ) do
        current_pwuid.name
      end
    end

    def self.initial_full_name
      self.default_boot_param( 'full_name' ) do
        current_pwuid.gecos.gsub(/,.*/, '')
      end
    end

    def self.initial_password
      self.default_boot_param( 'password' ) do
        Smartguard::Utils.random_chars[ 0..8 ]
      end
    end
    
  end

end
