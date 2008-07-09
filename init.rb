require 'access_test_helpers'
require 'access_form_helpers'
require 'access_require_privilege'
require 'access_sanity_tests'
require 'access'

require 'smartguard'
require 'smartguard_basic_role'
require 'smartguard_basic_permission'
require 'smartguard_basic_user'
require 'smartguard_basic_role_assignment'

# Monkeypatch for Oracle adapter...

require 'active_record/schema_dumper'
require 'smartguard_oracle_monkeypatch'


