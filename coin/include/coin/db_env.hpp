/*
 * Copyright (c) 2013-2016 John Connor
 * Copyright (c) 2016-2017 The Vcash developers
 *
 * This file is part of vcash.
 *
 * vcash is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef COIN_DB_ENV_HPP
#define COIN_DB_ENV_HPP

#include <db_cxx.h>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <coin/filesystem.hpp>

namespace coin {

    /**
     * Implements a berkley database DbEnv object wrapper.
     */
    class db_env
    {
        public:
        
            /**
             * The default cache size.
             */
            enum { default_cache_size = 25 };
        
            /**
             * Constructor
             */
            db_env();
        
            /**
             * Destructor
             */
            ~db_env();
        
            /**
             * Opens the database environment.
             * @param cache_size The cache size.
             */
            bool open(
                const std::int32_t & cache_size = default_cache_size
            );
        
            /**
             * Closes the DbEnv object.
             */
            void close_DbEnv();
        
            /**
             * Closes a Db object.
             * @param file_name The file name.
             */
            void close_Db(const std::string & file_name);
        
            /**
             * Removes a Db object.
             * @param file_name The file name.
             */
            bool remove_Db(const std::string & file_name);

            /**
             * Verifies that the database file is OK.
             * @param file_name The file name.
             */
            bool verify(const std::string & file_name);
    
            /**
             * Attempts to salvage data from a file.
             * @param file_name The file name.
             * @param aggressive If true the DB_AGGRESSIVE will be used.
             * @param result The result.
             */
            bool salvage(
                const std::string & file_name, const bool & aggressive,
                std::vector< std::pair< std::vector<std::uint8_t>,
                std::vector<std::uint8_t> > > & result
            );
    
            /**
             * checkpoint_lsn
             * @param file_name The file name.
             */
            void checkpoint_lsn(const std::string & file_name);
        
            /**
             * Flushes.
             * @param detach_db If true the database will be detached.
             */
            void flush(const bool & detach_db = false);
        
            /**
             * The DbEnv.
             */
            DbEnv & get_DbEnv();
        
            /**
             * The file use counts.
             */
            std::map<std::string, std::uint32_t> & file_use_counts();
        
            /**
             * The Db objects.
             */
            std::map<std::string, Db *> & Dbs();
        
            /**
             * The std::mutex.
             */
            static std::recursive_mutex & mutex_DbEnv();
        
            /**
             * txn_begin
             * @param flags The flags.
             */
            DbTxn * txn_begin(int flags = DB_TXN_WRITE_NOSYNC);
        
        private:
        
            /**
             * The DbEnv.
             */
            DbEnv m_DbEnv;
        
            /**
             * The file use counts.
             */
            std::map<std::string, std::uint32_t> m_file_use_counts;
        
            /**
             * The Db objects.
             */
            std::map<std::string, Db *> m_Dbs;
    
            /**
             * The m_DbEnv std::recursive_mutex.
             */
            static std::recursive_mutex g_mutex_DbEnv;
        
        protected:
        
            /**
             * The state.
             */
            enum
            {
                state_opened,
                state_closed,
            } state_;
        
            /**
             * m_file_use_counts std::recursive_mutex.
             */
            std::recursive_mutex mutex_file_use_counts_;
        
            /**
             * m_Dbs std::recursive_mutex.
             */
            std::recursive_mutex mutex_m_Dbs_;
    };
    
} // namespace coin

#endif // COIN_DB_ENV_HPP
