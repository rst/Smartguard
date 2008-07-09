module ActiveRecord
  module ConnectionAdapters
    class OracleAdapter < AbstractAdapter
      def select_values(sql, name = nil)
        result = select_all(sql, name)
        result.map{ |v| v.values.first }
      end
    end
  end
end
