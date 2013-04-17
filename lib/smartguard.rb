require 'smartguard/version'
require 'smartguard/access_test_helpers'
require 'smartguard/access_form_helpers'
require 'smartguard/access_require_privilege'
require 'smartguard/access_sanity_tests'
require 'smartguard/access'

require 'smartguard/smartguard'
require 'smartguard/smartguard_db_dependencies'
require 'smartguard/smartguard_basic_role'
require 'smartguard/smartguard_basic_permission'
require 'smartguard/smartguard_basic_user'
require 'smartguard/smartguard_basic_role_assignment'

# Monkeypatch for Oracle adapter...

require 'active_record/schema_dumper'
require 'smartguard/smartguard_oracle_monkeypatch'

