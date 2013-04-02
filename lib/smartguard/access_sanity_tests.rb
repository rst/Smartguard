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

module Access

  module SanityTests

    # Make sure that concrete classes have the modules with the
    # access control logic wired up... 

    def test_modules_plugged_in
      assert Role.ancestors.include?( SmartguardBasicRole )
      assert User.ancestors.include?( SmartguardBasicUser )
      assert Permission.ancestors.include?( SmartguardBasicPermission )
      assert RoleAssignment.ancestors.include?( SmartguardBasicRoleAssignment )
    end

    def test_defaulting
      assert_nil Smartguard::Bootstrap::boot_param( 'steam_knob' )
      with_env_set( 'boot_steam_knob', '4-6-2 pacific' ) do
        assert_equal '4-6-2 pacific', 
        Smartguard::Bootstrap::boot_param( 'steam_knob' )
      end
      assert_nil Smartguard::Bootstrap::boot_param( 'steam_knob' )
    end

    # Initial login/pw.  Might fail on Windows; if so, should disable.
    # On other platforms, just make sure we got *something*...

    def test_initial_login
      get_some_string_test( :initial_login, 'login' )
    end

    def test_initial_full_name
      get_some_string_test( :initial_full_name, 'full_name' )
    end

    def get_some_string_test( msg, key )

      first_val = expect_blurb(/#{key}/) { Smartguard::Bootstrap.send( msg ) }
      assert first_val.is_a?( String )
      assert first_val.length > 0
      assert_equal first_val, ENV["boot_#{key}"]

      with_env_set( "boot_#{key}", 'joe_doaks' ) do
        assert_equal 'joe_doaks', Smartguard::Bootstrap.send( msg )
      end
      
    end

    def test_password

      pw1 = expect_blurb(/password/) { Smartguard::Bootstrap.initial_password }
      sleep 1
      pw1a = expect_blurb(/^$/){ Smartguard::Bootstrap.initial_password }
      ENV['boot_password'] = nil
      pw2 = expect_blurb(/password/) { Smartguard::Bootstrap.initial_password }

      [pw1, pw2].each do |pw|
        assert pw.is_a?( String )
        assert pw.length > 6
      end

      assert_equal pw1, pw1a
      assert_not_equal pw1, pw2

    end

    private

    def with_env_set( k, v )
      saved_val = ENV[k]
      begin
        ENV[k] = v
        yield
      ensure
        ENV[k] = saved_val
      end
    end

    def expect_blurb( blurb_pat )
      new_stdout = StringIO.new
      begin
        $stdout = new_stdout
        value = yield
        new_stdout.rewind
        blurb = new_stdout.read
        assert_match blurb_pat, blurb 
        return value
      ensure
        $stdout = STDOUT
      end
    end

  end

end
