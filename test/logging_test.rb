#--
# Copyright (c) 2007 Robert S. Thau, Smartleaf, Inc.
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
require 'test_helper'

class LoggingTest < ActiveSupport::TestCase

  use_all_fixtures

  def test_logs_check_permission

    User.as( users(:ricky) ) do

      pcheck = extract_pcheck_from do
        roles(:ricardo_admin).check_permission!(:edit)
      end

      assert_equal 'Role',                   pcheck[:model_class]
      assert_equal 'edit',                   pcheck[:privilege]
      assert_equal roles(:ricardo_admin).id, pcheck[:model_id]
      assert                                 pcheck[:success]

      pcheck = extract_pcheck_from do
        assert_raises( PermissionFailure ) do
          roles(:mertz_admin).check_permission!(:edit)
        end
      end

      assert_equal 'Role',                   pcheck[:model_class]
      assert_equal 'edit',                   pcheck[:privilege]
      assert_equal roles(:mertz_admin).id,   pcheck[:model_id]
      assert                                 !pcheck[:success]

    end

  end

  def test_logs_assoc_checks

    User.as( users(:ricky) ) do

      pchecks = extract_pchecks_from do
        RoleAssignment.new :role_id => roles(:ricardo_admin).id
      end

      pcheck = pchecks.first

      assert_equal 'Role',                   pcheck[:model_class]
      assert_equal 'assign',                 pcheck[:privilege]
      assert_equal roles(:ricardo_admin).id, pcheck[:model_id]
      assert                                 pcheck[:success]

      pcheck = extract_pcheck_from do
        assert_raises( PermissionFailure ) do
          RoleAssignment.new :role => roles(:mertz_admin)
        end
      end

      assert_equal 'Role',                   pcheck[:model_class]
      assert_equal 'assign',                 pcheck[:privilege]
      assert_equal roles(:mertz_admin).id,   pcheck[:model_id]
      assert                                 !pcheck[:success]

    end

  end

  def test_logs_grant_checks

    User.as( users(:universal_grant_guy) ) do

      pchecks = extract_pchecks_from do
        perm = wildcard_perm( :post, Blog )
        perm.role = roles(:ricardo_admin)
        perm.save!
      end

      assert(pchecks.detect { |pcheck|
               pcheck[:model_class] == 'Permission' &&
               pcheck[:privilege]   == 'grant'      &&
               pcheck[:success]
             })
      
    end

    User.as( users(:ricky) ) do

      pchecks = extract_pchecks_from do
        perm = wildcard_perm( :post, Blog )
        perm.role = roles(:ricardo_admin)
        assert_raises( PermissionFailure ) do
          perm.save!
        end
      end

      assert( pchecks.detect { |pcheck|
        pcheck[:model_class] == 'Permission'    &&
        pcheck[:privilege]   == 'grant'         &&
        !pcheck[:success]
      })
      
    end

  end

  # Dumbest possible logging hook...

  @pcheck_buffer = nil

  Smartguard::Logging.add_hook do |h| 
    @pcheck_buffer << h unless @pcheck_buffer.nil? 
  end

  def extract_pcheck_from
    pchecks = extract_pchecks_from { yield }
    assert_equal 1, pchecks.size
    pchecks.first
  end

  def extract_pchecks_from( &blk )
    self.class.extract_pchecks_from( &blk )
  end

  def self.extract_pchecks_from( &blk )
    begin
      @pcheck_buffer = []
      blk.call()
      return @pcheck_buffer.dup
    ensure
      @pcheck_buffer = nil
    end
  end

end

