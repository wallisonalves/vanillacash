/*
 * Copyright (c) 2013-2016 John Connor
 * Copyright (c) 2016-2017 The Vcash Developers
 *
 * This file is part of Vcash.
 *
 * Vcash is free software: you can redistribute it and/or modify
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

#include <map>
#include <string>

#include <boost/asio.hpp>

#include <crawler/stack.hpp>


int main(int argc, const char * argv[])
{
    std::map<std::string, std::string> args;
    
    for (auto i = 0; i < argc; i++)
    {
        if (argv[i][0] == '-' && argv[i][1] == '-')
        {
            auto arg = std::string(argv[i]).substr(2, strlen(argv[i]));
            
            std::string key, value;
            
            auto i = arg.find("=");

            if (i != std::string::npos)
            {
                key = arg.substr(0, i);
                
                i = arg.find("=");
                
                if (i != std::string::npos)
                {
                    value = arg.substr(i + 1, arg.length());
                    
                    args[key] = value;
                }
            }
        }
    }
    
    boost::asio::io_service ios;

    /**
     * Allocate the crawler::stack.
     */
    crawler::stack s;
    
    /**
     * Start the crawler::stack.
     */
    s.start(args);
    
    boost::asio::signal_set signals(ios, SIGINT, SIGTERM);
    signals.async_wait(std::bind(&boost::asio::io_service::stop, &ios));
    ios.run();

    /**
     * Stop the crawler::stack.
     */
    s.stop();

    return 0;
}
