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

#include <cassert>

#include <coin/address_manager.hpp>
#include <coin/configuration.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/network.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/time.hpp>
#include <coin/utility.hpp>

using namespace coin;

tcp_connection_manager::tcp_connection_manager(
    boost::asio::io_service & ios, stack_impl & owner
    )
    : m_time_last_inbound(0)
    , io_service_(ios)
    , resolver_(ios)
    , strand_(globals::instance().strand())
    , stack_impl_(owner)
    , timer_(ios)
{
    // ...
}

void tcp_connection_manager::start()
{
    std::vector<boost::asio::ip::tcp::resolver::query> queries;
    
    /**
     * Get the bootstrap nodes and ready them for DNS lookup.
     */
    auto bootstrap_nodes = stack_impl_.get_configuration().bootstrap_nodes();
    
    for (auto & i : bootstrap_nodes)
    {
        boost::asio::ip::tcp::resolver::query q(
            i.first, std::to_string(i.second)
        );
        
        queries.push_back(q);
    }

    /**
     * Randomize the host names.
     */
    std::random_shuffle(queries.begin(), queries.end());
    
    /**
     * Start host name resolution.
     */
    do_resolve(queries);

    /**
     * Start the timer.
     */
    auto self(shared_from_this());
    
    timer_.expires_from_now(std::chrono::seconds(1));
    timer_.async_wait(globals::instance().strand().wrap(
        std::bind(&tcp_connection_manager::tick, self,
        std::placeholders::_1))
    );
}

void tcp_connection_manager::stop()
{
    resolver_.cancel();
    timer_.cancel();
    
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto connection = i.second.lock())
        {
            connection->stop();
        }
    }
    
    m_tcp_connections.clear();
}

void tcp_connection_manager::handle_accept(
    std::shared_ptr<tcp_transport> transport
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    try
    {
        if (
            transport->socket().remote_endpoint().address(
            ).is_loopback() == false && transport->socket().remote_endpoint(
            ).address().is_multicast() == false
            )
        {
            m_time_last_inbound = std::time(0);
        }
    }
    catch (...)
    {
        // ...
    }

    /**
     * Only peers accept incoming connections.
     */
    if (
        globals::instance().state() == globals::state_started &&
        globals::instance().operation_mode() == protocol::operation_mode_peer
        )
    {
        /**
         * We allow this many incoming connections per same IP address.
         */
        enum { maximum_per_same_ip = 6 };

        auto connections = 0;
        
        for (auto & i : m_tcp_connections)
        {
            try
            {
                if (auto t = i.second.lock())
                {
                    if (
                        t->is_transport_valid() && i.first.address() ==
                        transport->socket().remote_endpoint().address()
                        )
                    {
                        if (++connections == maximum_per_same_ip)
                        {
                            break;
                        }
                    }
                }
            }
            catch (...)
            {
                // ...
            }
        }
        
        if (connections > maximum_per_same_ip)
        {
            log_error(
                "TCP connection manager is dropping duplicate IP connection "
                "from " << transport->socket().remote_endpoint() << "."
            );
            
            /**
             * Stop the transport.
             */
            transport->stop();
        }
        else if (
            network::instance().is_address_banned(
            transport->socket().remote_endpoint().address().to_string())
            )
        {
            log_info(
                "TCP connection manager is dropping banned connection from " <<
                transport->socket().remote_endpoint() << ", limit reached."
            );
            
            /**
             * Stop the transport.
             */
            transport->stop();
        }
        else if (
            is_ip_banned(
            transport->socket().remote_endpoint().address().to_string())
            )
        {
            log_info(
                "TCP connection manager is dropping (static banned) "
                "connection from " << transport->socket().remote_endpoint() <<
                "."
            );
            
            /**
             * Stop the transport.
             */
            transport->stop();
        }
        else if (
            active_tcp_connections() >=
            stack_impl_.get_configuration().network_tcp_inbound_maximum()
            )
        {
            /**
             * Allow 16 (short term) connection slots beyond our maximum.
             */
            if (
                active_tcp_connections() >=
                stack_impl_.get_configuration(
                ).network_tcp_inbound_maximum() + 16
                )
            {
                log_info(
                    "TCP connection manager is dropping "
                    "connection from " <<
                    transport->socket().remote_endpoint() <<
                    ", limit reached."
                );
                
                /**
                 * Stop the transport.
                 */
                transport->stop();
            }
            else
            {
                log_info(
                    "TCP connection manager allowing (short term) connection "
                    "from " << transport->socket().remote_endpoint() << ", "
                    "limit reached."
                );
                
                /**
                 * Allocate the tcp_connection.
                 */
                auto connection = std::make_shared<tcp_connection> (
                    io_service_, stack_impl_, tcp_connection::direction_incoming,
                    transport
                );

                /**
                 * Retain the connection.
                 */
                m_tcp_connections[transport->socket().remote_endpoint()] =
                    connection
                ;
                
                /**
                 * Start the tcp_connection.
                 */
                connection->start();
                
                /**
                 * Stop the connection (after 8 seconds).
                 */
                connection->stop_after(8);
            }
        }
        else
        {
            log_debug(
                "TCP connection manager accepted new tcp connection from " <<
                transport->socket().remote_endpoint() << ", " <<
                m_tcp_connections.size() << " connected peers."
            );

            /**
             * Allocate the tcp_connection.
             */
            auto connection = std::make_shared<tcp_connection> (
                io_service_, stack_impl_, tcp_connection::direction_incoming,
                transport
            );

            /**
             * Retain the connection.
             */
            m_tcp_connections[transport->socket().remote_endpoint()] =
                connection
            ;
            
            /**
             * Start the tcp_connection.
             */
            connection->start();
        }
    }
}

void tcp_connection_manager::broadcast(
    const char * buf, const std::size_t & len
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto j = i.second.lock())
        {
            j->send(buf, len);
        }
    }
}

void tcp_connection_manager::broadcast_bip0037(
    const char * buf, const std::size_t & len
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto j = i.second.lock())
        {
            /**
             * Skip the bip0037 tcp_connection with relay = false.
             */
            if (j->protocol_version_relay() == false)
            {
                continue;
            }
            else
            {
                j->send(buf, len);
            }
        }
    }
}

std::map< boost::asio::ip::tcp::endpoint, std::weak_ptr<tcp_connection> > &
    tcp_connection_manager::tcp_connections()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    return m_tcp_connections;
}

std::size_t tcp_connection_manager::active_tcp_connections()
{
    std::size_t ret = 0;
    
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto connection = i.second.lock())
        {
            if (connection->is_transport_valid())
            {
                if (auto t = connection->get_tcp_transport().lock())
                {
                    if (t->state() == tcp_transport::state_connected)
                    {
                        ++ret;
                    }
                }
            }
        }
    }
    
    return ret;
}

bool tcp_connection_manager::is_connected()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    auto tcp_connections = 0;
    
    for (auto & i : m_tcp_connections)
    {
        if (auto connection = i.second.lock())
        {
            if (auto t = connection->get_tcp_transport().lock())
            {
                if (t->state() == tcp_transport::state_connected)
                {
                    ++tcp_connections;
                }
            }
        }
    }
    
    return tcp_connections > 0;
}

std::size_t tcp_connection_manager::minimum_tcp_connections()
{
    /**
     * SPV clients download the headers from a single peer until the last
     * checkpoint is near at which point we increase the connection count
     * to 3 peers and switch to getblocks. When connected to three peers we
     * only download from one of them rotating as needed but accept blocks
     * from all connections that advertise them.
     */
    if (globals::instance().is_client_spv() == true)
    {
        if (
            globals::instance().spv_block_last() == 0 ||
            globals::instance().spv_use_getblocks() == false
            )
        {
            return 1;
        }
    
        return 3;
    }

    return utility::is_initial_block_download() ? 3 : 8;
}

const std::time_t & tcp_connection_manager::time_last_inbound() const
{
    return m_time_last_inbound;
}

bool tcp_connection_manager::connect(const boost::asio::ip::tcp::endpoint & ep)
{
    if (globals::instance().state() == globals::state_started)
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
        
        if (network::instance().is_address_banned(ep.address().to_string()))
        {
            log_info(
                "TCP connection manager tried to connect to a banned "
                "address " << ep << "."
            );
            
            return false;
        }
        else if (is_ip_banned(ep.address().to_string()))
        {
            log_debug(
                "TCP connection manager tried to connect to a bad address " <<
                ep << "."
            );
            
            return false;
        }
        else if (m_tcp_connections.find(ep) == m_tcp_connections.end())
        {
            log_none("TCP connection manager is connecting to " << ep << ".");
            
            /**
             * Inform the address_manager.
             */
            stack_impl_.get_address_manager()->on_connection_attempt(
                protocol::network_address_t::from_endpoint(ep)
            );
            
            /**
             * Allocate tcp_transport.
             */
            auto transport = std::make_shared<tcp_transport>(
                io_service_, strand_
            );
            
            /**
             * Allocate the tcp_connection.
             */
            auto connection = std::make_shared<tcp_connection> (
                io_service_, stack_impl_, tcp_connection::direction_outgoing,
                transport
            );
            
            /**
             * Retain the connection.
             */
            m_tcp_connections[ep] = connection;
            
            /**
             * Start the tcp_connection.
             */
            connection->start(ep);
            
            return true;
        }
        else
        {
            log_none(
                "TCP connection manager attempted connection to existing "
                "endpoint = " << ep << "."
            );
        }
    }
    
    return false;
}

void tcp_connection_manager::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
        
        auto tcp_connections = 0;
        auto outgoing_tcp_connections = 0;
        
        auto it = m_tcp_connections.begin();
        
        while (it != m_tcp_connections.end())
        {
            if (auto connection = it->second.lock())
            {
                if (connection->is_transport_valid())
                {
                    if (auto t = connection->get_tcp_transport().lock())
                    {
                        if (t->state() == tcp_transport::state_connected)
                        {
                            ++tcp_connections;
                            
                            if (
                                connection->direction() ==
                                tcp_connection::direction_outgoing
                                )
                            {
                                ++outgoing_tcp_connections;
                            }
                        }
                    }
                    
                    ++it;
                }
                else
                {    
                    connection->stop();
                    
                    it = m_tcp_connections.erase(it);
                }
            }
            else
            {
                it = m_tcp_connections.erase(it);
            }
        }
        
        /**
         * Get if we are in initial download.
         */
        auto is_initial_block_download =
            globals::instance().is_client_spv() ?
            utility::is_spv_initial_block_download() :
            utility::is_initial_block_download()
        ;

        if (is_initial_block_download == false)
        {
            /**
             * Enforce the minimum_tcp_connections (outgoing).
             */
            if (outgoing_tcp_connections > minimum_tcp_connections())
            {
                auto it = m_tcp_connections.begin();
                
                std::advance(it, std::rand() % m_tcp_connections.size());
                
                if (auto connection = it->second.lock())
                {
                    if (
                        connection->direction() ==
                        tcp_connection::direction_outgoing
                        )
                    {
                        m_tcp_connections.erase(it);
                    }
                }
            }
        }
        
        /**
         * Maintain at least minimum_tcp_connections tcp connections.
         */
        if (tcp_connections < minimum_tcp_connections())
        {
            for (
                auto i = 0; i < minimum_tcp_connections() -
                tcp_connections; i++
                )
            {
                /**
                 * Get a network address from the address_manager.
                 */
                auto addr = stack_impl_.get_address_manager()->select(
                    10 + std::min(m_tcp_connections.size(),
                    static_cast<std::size_t> (8)) * 10
                );
            
                /**
                 * Only connect to one peer per group.
                 */
                auto is_in_same_group = false;

                for (auto & i : m_tcp_connections)
                {
                    if (auto j = i.second.lock())
                    {
                        if (auto k = j->get_tcp_transport().lock())
                        {
                            try
                            {
                                auto addr_tmp =
                                    protocol::network_address_t::from_endpoint(
                                    k->socket().remote_endpoint()
                                );
                                
                                if (addr.group() == addr_tmp.group())
                                {
                                    is_in_same_group = true;
                                }
                            }
                            catch (std::exception & e)
                            {
                                // ...
                            }
                        }
                    }
                }

                if (
                    constants::test_net == false &&
                    (addr.is_valid() == false || addr.is_local() ||
                    is_in_same_group)
                    )
                {
                    // ...
                }
                else
                {
                    /**
                     * Do not retry connections to the same network address more
                     * often than every 60 seconds.
                     */
                    if (
                        constants::test_net == false &&
                        std::time(0) - addr.last_try < 60
                        )
                    {
                        log_info(
                            "TCP connection manager attempted to "
                            "connect to " << addr.ipv4_mapped_address() <<
                            ":" << addr.port << " too soon, last try = " <<
                            (time::instance().get_adjusted() - addr.last_try) <<
                            " seconds."
                        );
                    }
                    else
                    {
                        /**
                         * Connect to the endpoint.
                         */
                        if (connect(
                            boost::asio::ip::tcp::endpoint(
                            addr.ipv4_mapped_address(), addr.port))
                            )
                        {
                            log_info(
                                "TCP connection manager is connecting to " <<
                                addr.ipv4_mapped_address() << ":" <<
                                addr.port << ", last seen = " <<
                                (time::instance().get_adjusted() -
                                addr.timestamp) / 60 << " mins, " <<
                                tcp_connections << " connected peers."
                            );
                        }
                    }
                }
            }
            
            auto self(shared_from_this());
            
            timer_.expires_from_now(std::chrono::seconds(1));
            timer_.async_wait(globals::instance().strand().wrap(
                std::bind(&tcp_connection_manager::tick, self,
                std::placeholders::_1))
            );
        }
        else
        {
            auto self(shared_from_this());
            
            timer_.expires_from_now(std::chrono::seconds(8));
            timer_.async_wait(globals::instance().strand().wrap(
                std::bind(&tcp_connection_manager::tick, self,
                std::placeholders::_1))
            );
        }

        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the status message.
         */
        status["type"] = "network";
        
        /**
         * Set the value.
         */
        status["value"] = tcp_connections > 0 ? "Connected" : "Connecting";
        
        /**
         * Set the network.tcp.connections.
         */
        status["network.tcp.connections"] = std::to_string(
            tcp_connections
        );
        
        /**
         * Callback status.
         */
        stack_impl_.get_status_manager()->insert(status);
    }
}

void tcp_connection_manager::do_resolve(
    const std::vector<boost::asio::ip::tcp::resolver::query> & queries
    )
{
    /**
     * Sanity check.
     */
    assert(queries.size() <= 100);
    
    /**
     * Resolve the first entry.
     */
    resolver_.async_resolve(queries.front(),
        strand_.wrap([this, queries](
            const boost::system::error_code & ec,
            const boost::asio::ip::tcp::resolver::iterator & it
            )
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    log_debug(
                        "TCP connection manager resolved " << it->endpoint() <<
                        "."
                    );
                    
                    /**
                     * Create the network address.
                     */
                    protocol::network_address_t addr =
                        protocol::network_address_t::from_endpoint(
                        it->endpoint()
                    );
                    
                    /**
                     * Add to the address manager.
                     */
                    stack_impl_.get_address_manager()->add(
                        addr, protocol::network_address_t::from_endpoint(
                        boost::asio::ip::tcp::endpoint(
                        boost::asio::ip::address::from_string("127.0.0.1"), 0))
                    );
                }
                
                if (queries.size() > 0)
                {
                    auto tmp = queries;
                    
                    /**
                     * Remove the first entry.
                     */
                    tmp.erase(tmp.begin());
                    
                    if (tmp.size() > 0)
                    {
                        /**
                         * Keep resolving as long as we have entries.
                         */
                        do_resolve(tmp);
                    }
                }
            }
        )
    );
}

bool tcp_connection_manager::is_ip_banned(const std::string & val)
{
    /**
     * Amazon EC2 IP's.
     */
    if (
        (val[0] == '5' && val[1] == '4') ||
        (val[0] == '5' && val[1] == '0') ||
        (val[0] == '2' && val[1] == '1' && val[2] == '1') ||
        (val[0] == '2' && val[1] == '1' && val[2] == '9')
        )
    {
        return true;
    }
    
    /**
     * Known attack IP's.
     */
    static const std::map<std::string, std::int32_t> g_known_attack_ips =
    {
#if 0
        {"113.97.218.52", -1}
#endif
    };
    
    if (g_known_attack_ips.count(val) > 0)
    {
        return true;
    }
    
    /**
     * ToR exit IP's. #1162; This file was generated on Tue Sep 11 11:04:12 UTC 2018
     */
    static const std::map<std::string, std::int32_t> g_tor_exit_ips =
    {
        {"2.243.86.137", -1},
        {"2.243.116.89", -1},
        {"2.247.55.22", -1},
        {"5.2.77.146", -1},
        {"5.3.131.113", -1},
        {"5.3.132.89", -1},
        {"5.3.133.73", -1},
        {"5.3.133.95", -1},
        {"5.3.136.153", -1},
        {"5.3.137.167", -1},
        {"5.3.141.220", -1},
        {"5.3.142.127", -1},
        {"5.9.9.18", -1},
        {"5.9.158.75", -1},
        {"5.9.195.140", -1},
        {"5.34.183.105", -1},
        {"5.39.217.14", -1},
        {"5.79.113.168", -1},
        {"5.79.113.223", -1},
        {"5.79.119.219", -1},
        {"5.101.40.89", -1},
        {"5.135.158.101", -1},
        {"5.165.72.79", -1},
        {"5.165.76.151", -1},
        {"5.165.78.95", -1},
        {"5.187.21.43", -1},
        {"5.189.146.133", -1},
        {"5.196.1.129", -1},
        {"5.196.66.162", -1},
        {"5.199.130.127", -1},
        {"5.248.11.76", -1},
        {"5.248.11.154", -1},
        {"5.248.126.45", -1},
        {"18.18.248.17", -1},
        {"18.18.248.40", -1},
        {"18.85.22.239", -1},
        {"23.129.64.101", -1},
        {"23.129.64.102", -1},
        {"23.129.64.103", -1},
        {"23.129.64.104", -1},
        {"23.129.64.105", -1},
        {"23.129.64.106", -1},
        {"23.239.23.104", -1},
        {"24.3.109.151", -1},
        {"24.3.111.83", -1},
        {"27.56.174.106", -1},
        {"27.124.124.126", -1},
        {"31.31.72.24", -1},
        {"31.31.74.131", -1},
        {"31.131.2.19", -1},
        {"31.131.4.171", -1},
        {"31.171.155.131", -1},
        {"31.185.27.201", -1},
        {"31.185.104.19", -1},
        {"31.185.104.20", -1},
        {"31.185.104.21", -1},
        {"31.204.151.147", -1},
        {"31.220.42.86", -1},
        {"35.0.127.52", -1},
        {"35.205.205.119", -1},
        {"35.240.31.111", -1},
        {"35.248.27.205", -1},
        {"37.48.120.196", -1},
        {"37.59.112.7", -1},
        {"37.112.210.172", -1},
        {"37.112.211.133", -1},
        {"37.112.216.215", -1},
        {"37.113.6.138", -1},
        {"37.128.222.30", -1},
        {"37.139.8.104", -1},
        {"37.187.7.74", -1},
        {"37.187.94.86", -1},
        {"37.187.129.166", -1},
        {"37.187.180.18", -1},
        {"37.218.240.21", -1},
        {"37.218.240.68", -1},
        {"37.218.240.80", -1},
        {"37.218.240.110", -1},
        {"37.218.245.25", -1},
        {"37.220.36.240", -1},
        {"37.228.129.2", -1},
        {"37.233.102.65", -1},
        {"37.233.103.114", -1},
        {"40.69.62.87", -1},
        {"41.100.5.173", -1},
        {"41.100.88.178", -1},
        {"41.100.113.238", -1},
        {"41.100.132.108", -1},
        {"41.100.163.230", -1},
        {"41.100.163.252", -1},
        {"41.101.223.157", -1},
        {"41.103.212.111", -1},
        {"45.23.105.21", -1},
        {"45.32.116.97", -1},
        {"45.33.48.204", -1},
        {"45.35.72.85", -1},
        {"45.62.236.67", -1},
        {"45.62.251.245", -1},
        {"45.76.115.159", -1},
        {"45.79.1.190", -1},
        {"45.79.85.112", -1},
        {"45.79.144.222", -1},
        {"46.4.86.164", -1},
        {"46.17.46.199", -1},
        {"46.29.248.238", -1},
        {"46.36.35.96", -1},
        {"46.36.38.57", -1},
        {"46.38.235.14", -1},
        {"46.41.150.74", -1},
        {"46.98.196.38", -1},
        {"46.98.196.50", -1},
        {"46.98.196.171", -1},
        {"46.98.196.199", -1},
        {"46.98.196.221", -1},
        {"46.98.196.238", -1},
        {"46.98.197.30", -1},
        {"46.98.197.53", -1},
        {"46.98.197.56", -1},
        {"46.98.197.120", -1},
        {"46.98.197.169", -1},
        {"46.98.197.175", -1},
        {"46.98.197.178", -1},
        {"46.98.197.219", -1},
        {"46.98.197.246", -1},
        {"46.98.197.248", -1},
        {"46.98.198.10", -1},
        {"46.98.198.85", -1},
        {"46.98.198.140", -1},
        {"46.98.198.142", -1},
        {"46.98.198.152", -1},
        {"46.98.198.167", -1},
        {"46.98.198.203", -1},
        {"46.98.198.235", -1},
        {"46.98.198.246", -1},
        {"46.98.199.6", -1},
        {"46.98.199.78", -1},
        {"46.98.199.118", -1},
        {"46.98.199.127", -1},
        {"46.98.199.131", -1},
        {"46.98.199.145", -1},
        {"46.98.199.172", -1},
        {"46.98.199.183", -1},
        {"46.98.199.224", -1},
        {"46.98.199.241", -1},
        {"46.98.199.255", -1},
        {"46.98.200.12", -1},
        {"46.98.200.50", -1},
        {"46.98.200.93", -1},
        {"46.98.200.114", -1},
        {"46.98.200.122", -1},
        {"46.98.200.176", -1},
        {"46.98.200.206", -1},
        {"46.98.200.220", -1},
        {"46.98.200.248", -1},
        {"46.98.201.39", -1},
        {"46.98.201.67", -1},
        {"46.98.201.112", -1},
        {"46.98.201.162", -1},
        {"46.98.201.164", -1},
        {"46.98.201.230", -1},
        {"46.98.201.237", -1},
        {"46.98.202.21", -1},
        {"46.98.202.28", -1},
        {"46.98.202.102", -1},
        {"46.98.202.149", -1},
        {"46.98.202.152", -1},
        {"46.98.202.199", -1},
        {"46.98.203.13", -1},
        {"46.98.203.24", -1},
        {"46.98.203.78", -1},
        {"46.98.203.81", -1},
        {"46.98.203.91", -1},
        {"46.98.203.95", -1},
        {"46.98.203.138", -1},
        {"46.98.203.184", -1},
        {"46.98.203.216", -1},
        {"46.98.204.67", -1},
        {"46.98.204.82", -1},
        {"46.98.204.92", -1},
        {"46.98.204.132", -1},
        {"46.98.204.161", -1},
        {"46.98.205.10", -1},
        {"46.98.205.32", -1},
        {"46.98.205.65", -1},
        {"46.98.205.69", -1},
        {"46.98.205.82", -1},
        {"46.98.205.149", -1},
        {"46.98.205.160", -1},
        {"46.98.205.175", -1},
        {"46.98.205.197", -1},
        {"46.98.205.200", -1},
        {"46.98.205.239", -1},
        {"46.98.206.151", -1},
        {"46.98.206.208", -1},
        {"46.98.206.233", -1},
        {"46.98.207.60", -1},
        {"46.98.207.110", -1},
        {"46.98.207.142", -1},
        {"46.98.208.2", -1},
        {"46.98.208.15", -1},
        {"46.98.208.49", -1},
        {"46.98.208.52", -1},
        {"46.98.208.73", -1},
        {"46.98.208.75", -1},
        {"46.98.208.81", -1},
        {"46.98.208.180", -1},
        {"46.98.208.197", -1},
        {"46.98.208.236", -1},
        {"46.98.209.13", -1},
        {"46.98.209.43", -1},
        {"46.98.209.53", -1},
        {"46.98.209.116", -1},
        {"46.98.209.132", -1},
        {"46.98.209.156", -1},
        {"46.98.209.168", -1},
        {"46.98.209.225", -1},
        {"46.98.209.230", -1},
        {"46.98.209.252", -1},
        {"46.101.61.36", -1},
        {"46.105.84.15", -1},
        {"46.165.230.5", -1},
        {"46.165.254.166", -1},
        {"46.166.129.156", -1},
        {"46.166.139.35", -1},
        {"46.173.214.3", -1},
        {"46.182.18.29", -1},
        {"46.182.18.40", -1},
        {"46.182.19.15", -1},
        {"46.182.106.190", -1},
        {"46.183.218.80", -1},
        {"46.183.221.155", -1},
        {"46.194.2.86", -1},
        {"46.194.177.95", -1},
        {"46.223.202.46", -1},
        {"46.226.108.26", -1},
        {"46.233.0.70", -1},
        {"46.235.227.70", -1},
        {"46.246.35.20", -1},
        {"46.246.35.109", -1},
        {"46.246.36.103", -1},
        {"46.246.40.158", -1},
        {"46.246.41.6", -1},
        {"46.246.44.148", -1},
        {"46.246.49.138", -1},
        {"46.246.49.142", -1},
        {"46.246.49.148", -1},
        {"46.246.49.157", -1},
        {"46.246.49.182", -1},
        {"46.246.49.183", -1},
        {"46.246.49.186", -1},
        {"46.246.49.190", -1},
        {"46.246.49.195", -1},
        {"46.246.49.211", -1},
        {"46.246.49.216", -1},
        {"46.246.49.224", -1},
        {"46.246.49.227", -1},
        {"46.246.49.237", -1},
        {"46.246.61.190", -1},
        {"50.116.37.141", -1},
        {"50.247.195.124", -1},
        {"51.15.34.214", -1},
        {"51.15.43.205", -1},
        {"51.15.49.134", -1},
        {"51.15.53.83", -1},
        {"51.15.57.167", -1},
        {"51.15.65.25", -1},
        {"51.15.68.66", -1},
        {"51.15.72.211", -1},
        {"51.15.80.14", -1},
        {"51.15.81.222", -1},
        {"51.15.82.2", -1},
        {"51.15.88.249", -1},
        {"51.15.116.141", -1},
        {"51.15.123.230", -1},
        {"51.15.124.1", -1},
        {"51.15.205.214", -1},
        {"51.15.209.128", -1},
        {"51.15.224.0", -1},
        {"51.15.233.253", -1},
        {"51.15.240.100", -1},
        {"51.38.69.128", -1},
        {"51.38.110.166", -1},
        {"51.38.113.64", -1},
        {"51.38.134.189", -1},
        {"51.38.146.239", -1},
        {"51.38.162.232", -1},
        {"51.75.19.170", -1},
        {"51.254.48.93", -1},
        {"51.254.127.93", -1},
        {"51.254.208.245", -1},
        {"51.254.209.128", -1},
        {"51.255.202.66", -1},
        {"54.36.189.105", -1},
        {"54.36.222.37", -1},
        {"54.37.16.241", -1},
        {"54.38.132.209", -1},
        {"54.38.228.98", -1},
        {"54.39.119.65", -1},
        {"54.39.119.66", -1},
        {"54.39.119.68", -1},
        {"54.39.119.69", -1},
        {"54.39.119.71", -1},
        {"54.39.119.72", -1},
        {"54.39.119.73", -1},
        {"54.39.119.74", -1},
        {"58.153.113.95", -1},
        {"59.115.211.170", -1},
        {"59.115.217.8", -1},
        {"59.127.163.155", -1},
        {"62.102.148.67", -1},
        {"62.141.37.236", -1},
        {"62.141.39.8", -1},
        {"62.205.133.251", -1},
        {"62.210.37.82", -1},
        {"62.210.71.205", -1},
        {"62.210.105.86", -1},
        {"62.210.105.116", -1},
        {"62.210.110.181", -1},
        {"62.210.116.201", -1},
        {"62.210.129.246", -1},
        {"62.210.157.133", -1},
        {"62.212.73.141", -1},
        {"64.27.17.140", -1},
        {"64.113.32.29", -1},
        {"64.137.220.248", -1},
        {"64.137.221.22", -1},
        {"64.137.221.225", -1},
        {"64.137.221.226", -1},
        {"64.137.226.112", -1},
        {"64.137.242.29", -1},
        {"64.190.90.60", -1},
        {"64.250.228.194", -1},
        {"65.19.167.130", -1},
        {"65.19.167.131", -1},
        {"65.19.167.132", -1},
        {"65.181.123.254", -1},
        {"66.42.224.235", -1},
        {"66.70.217.179", -1},
        {"66.110.216.10", -1},
        {"66.146.193.33", -1},
        {"66.155.4.213", -1},
        {"66.175.208.248", -1},
        {"66.175.211.27", -1},
        {"66.222.153.25", -1},
        {"67.1.161.184", -1},
        {"67.1.164.83", -1},
        {"67.215.255.140", -1},
        {"68.7.189.65", -1},
        {"68.7.190.238", -1},
        {"68.32.181.128", -1},
        {"69.162.107.5", -1},
        {"69.164.207.234", -1},
        {"70.168.93.214", -1},
        {"71.19.144.106", -1},
        {"72.14.179.10", -1},
        {"72.52.75.27", -1},
        {"72.207.120.199", -1},
        {"72.207.122.221", -1},
        {"72.210.252.137", -1},
        {"74.115.25.12", -1},
        {"77.14.33.26", -1},
        {"77.14.45.22", -1},
        {"77.14.72.93", -1},
        {"77.14.117.27", -1},
        {"77.73.65.100", -1},
        {"77.81.247.72", -1},
        {"77.179.63.106", -1},
        {"77.179.164.39", -1},
        {"77.179.216.20", -1},
        {"77.180.1.29", -1},
        {"77.180.69.1", -1},
        {"77.180.79.40", -1},
        {"77.247.181.163", -1},
        {"77.247.181.165", -1},
        {"78.31.164.41", -1},
        {"78.41.115.145", -1},
        {"78.53.140.66", -1},
        {"78.55.190.124", -1},
        {"78.55.246.194", -1},
        {"78.107.237.16", -1},
        {"78.109.23.1", -1},
        {"78.142.19.43", -1},
        {"78.142.175.70", -1},
        {"79.134.234.247", -1},
        {"79.137.68.85", -1},
        {"80.67.172.162", -1},
        {"80.68.92.225", -1},
        {"80.79.23.7", -1},
        {"80.82.215.17", -1},
        {"80.211.94.31", -1},
        {"80.211.156.90", -1},
        {"80.241.60.207", -1},
        {"81.4.0.6", -1},
        {"81.16.136.29", -1},
        {"81.171.2.229", -1},
        {"81.171.24.199", -1},
        {"81.231.177.43", -1},
        {"82.94.132.34", -1},
        {"82.118.242.128", -1},
        {"82.221.101.67", -1},
        {"82.221.139.25", -1},
        {"82.221.139.190", -1},
        {"82.221.141.96", -1},
        {"82.223.14.245", -1},
        {"82.223.27.82", -1},
        {"82.228.252.20", -1},
        {"82.247.198.227", -1},
        {"82.253.108.203", -1},
        {"84.0.40.53", -1},
        {"84.3.10.87", -1},
        {"84.16.240.74", -1},
        {"84.19.180.139", -1},
        {"84.19.181.25", -1},
        {"84.19.181.139", -1},
        {"84.48.199.78", -1},
        {"84.194.130.155", -1},
        {"84.195.252.128", -1},
        {"84.200.4.239", -1},
        {"84.200.50.18", -1},
        {"84.209.48.106", -1},
        {"84.217.13.138", -1},
        {"85.93.218.204", -1},
        {"85.166.129.127", -1},
        {"85.166.131.116", -1},
        {"85.166.131.218", -1},
        {"85.180.57.60", -1},
        {"85.182.31.69", -1},
        {"85.199.141.237", -1},
        {"85.248.227.163", -1},
        {"85.248.227.164", -1},
        {"85.248.227.165", -1},
        {"87.65.190.155", -1},
        {"87.118.92.43", -1},
        {"87.118.116.12", -1},
        {"87.118.116.90", -1},
        {"87.118.122.30", -1},
        {"87.118.122.50", -1},
        {"87.118.122.51", -1},
        {"87.118.122.254", -1},
        {"87.120.254.204", -1},
        {"87.233.197.114", -1},
        {"87.247.111.222", -1},
        {"88.76.25.56", -1},
        {"88.76.66.236", -1},
        {"88.77.157.61", -1},
        {"88.77.182.234", -1},
        {"88.77.197.7", -1},
        {"88.77.213.60", -1},
        {"88.77.214.12", -1},
        {"88.77.217.189", -1},
        {"89.31.57.5", -1},
        {"89.31.96.168", -1},
        {"89.33.246.73", -1},
        {"89.144.12.17", -1},
        {"89.187.150.12", -1},
        {"89.187.150.13", -1},
        {"89.187.150.14", -1},
        {"89.187.150.15", -1},
        {"89.234.157.254", -1},
        {"89.236.34.117", -1},
        {"91.92.109.43", -1},
        {"91.92.109.119", -1},
        {"91.146.121.3", -1},
        {"91.192.81.196", -1},
        {"91.219.236.171", -1},
        {"91.219.237.244", -1},
        {"91.250.114.46", -1},
        {"92.42.45.147", -1},
        {"92.63.103.241", -1},
        {"92.63.173.28", -1},
        {"92.195.25.97", -1},
        {"92.195.50.188", -1},
        {"92.195.83.5", -1},
        {"92.195.86.229", -1},
        {"92.195.103.103", -1},
        {"92.195.108.16", -1},
        {"92.222.38.67", -1},
        {"92.223.105.164", -1},
        {"92.231.184.192", -1},
        {"92.231.186.42", -1},
        {"93.81.254.231", -1},
        {"93.115.86.8", -1},
        {"93.115.95.202", -1},
        {"93.115.95.205", -1},
        {"93.115.95.206", -1},
        {"93.157.1.22", -1},
        {"93.170.123.11", -1},
        {"93.174.93.133", -1},
        {"93.190.40.143", -1},
        {"94.16.115.102", -1},
        {"94.16.123.176", -1},
        {"94.23.201.80", -1},
        {"94.45.135.106", -1},
        {"94.102.49.197", -1},
        {"94.102.51.78", -1},
        {"94.142.242.84", -1},
        {"94.156.77.134", -1},
        {"94.156.144.239", -1},
        {"94.199.215.172", -1},
        {"94.221.106.117", -1},
        {"94.221.108.106", -1},
        {"94.221.114.16", -1},
        {"94.221.120.27", -1},
        {"94.221.122.242", -1},
        {"94.221.125.124", -1},
        {"94.230.208.147", -1},
        {"94.230.208.148", -1},
        {"94.242.57.2", -1},
        {"94.242.57.161", -1},
        {"94.248.3.79", -1},
        {"94.248.3.86", -1},
        {"94.248.5.55", -1},
        {"94.248.5.160", -1},
        {"94.248.5.218", -1},
        {"94.248.6.180", -1},
        {"94.248.7.160", -1},
        {"94.248.8.220", -1},
        {"94.248.10.2", -1},
        {"94.248.11.76", -1},
        {"94.248.11.83", -1},
        {"94.248.14.125", -1},
        {"94.248.17.15", -1},
        {"94.248.17.68", -1},
        {"94.248.17.229", -1},
        {"94.248.18.198", -1},
        {"94.248.18.204", -1},
        {"95.46.44.213", -1},
        {"95.128.43.164", -1},
        {"95.130.9.90", -1},
        {"95.130.9.210", -1},
        {"95.130.10.69", -1},
        {"95.130.11.170", -1},
        {"95.130.12.33", -1},
        {"95.142.161.63", -1},
        {"95.143.193.125", -1},
        {"95.211.118.194", -1},
        {"95.215.44.194", -1},
        {"95.216.141.155", -1},
        {"95.216.145.1", -1},
        {"95.216.154.80", -1},
        {"97.74.237.196", -1},
        {"98.143.192.1", -1},
        {"98.143.192.2", -1},
        {"98.143.192.3", -1},
        {"98.143.192.4", -1},
        {"98.143.192.5", -1},
        {"98.143.192.6", -1},
        {"98.143.192.7", -1},
        {"98.143.192.8", -1},
        {"98.143.192.9", -1},
        {"98.143.192.10", -1},
        {"98.143.192.11", -1},
        {"98.143.192.12", -1},
        {"98.143.192.13", -1},
        {"98.143.192.14", -1},
        {"98.143.192.15", -1},
        {"98.143.192.16", -1},
        {"98.143.192.17", -1},
        {"98.143.192.18", -1},
        {"98.143.192.19", -1},
        {"98.143.192.20", -1},
        {"98.174.90.43", -1},
        {"103.1.206.109", -1},
        {"103.3.61.114", -1},
        {"103.8.79.229", -1},
        {"103.27.124.82", -1},
        {"103.28.52.93", -1},
        {"103.28.53.138", -1},
        {"103.87.8.163", -1},
        {"103.234.220.195", -1},
        {"103.234.220.197", -1},
        {"103.236.201.110", -1},
        {"103.250.73.13", -1},
        {"104.191.31.69", -1},
        {"104.200.20.46", -1},
        {"104.218.63.72", -1},
        {"104.218.63.73", -1},
        {"104.218.63.74", -1},
        {"104.218.63.75", -1},
        {"104.218.63.76", -1},
        {"104.218.63.77", -1},
        {"104.223.49.66", -1},
        {"104.223.123.98", -1},
        {"104.244.73.126", -1},
        {"104.244.74.59", -1},
        {"104.244.74.78", -1},
        {"104.244.75.82", -1},
        {"104.244.76.13", -1},
        {"104.244.76.50", -1},
        {"104.244.78.207", -1},
        {"104.248.61.234", -1},
        {"106.212.182.60", -1},
        {"107.172.242.216", -1},
        {"107.181.161.182", -1},
        {"107.181.174.66", -1},
        {"107.181.187.55", -1},
        {"108.211.142.83", -1},
        {"109.69.67.17", -1},
        {"109.70.100.18", -1},
        {"109.128.136.87", -1},
        {"109.162.63.23", -1},
        {"109.162.63.248", -1},
        {"109.169.33.163", -1},
        {"109.194.218.49", -1},
        {"109.201.133.100", -1},
        {"109.248.9.8", -1},
        {"110.227.137.75", -1},
        {"111.90.141.83", -1},
        {"114.24.103.100", -1},
        {"114.24.141.110", -1},
        {"114.24.210.9", -1},
        {"115.70.208.19", -1},
        {"116.93.119.149", -1},
        {"118.163.74.160", -1},
        {"121.102.82.70", -1},
        {"122.116.50.42", -1},
        {"122.161.130.217", -1},
        {"122.176.129.202", -1},
        {"122.176.130.168", -1},
        {"124.109.1.207", -1},
        {"125.212.241.182", -1},
        {"128.199.47.160", -1},
        {"128.199.76.145", -1},
        {"128.199.213.157", -1},
        {"128.199.237.114", -1},
        {"130.149.80.199", -1},
        {"130.204.161.3", -1},
        {"133.218.9.240", -1},
        {"133.236.13.191", -1},
        {"134.249.122.104", -1},
        {"134.249.202.20", -1},
        {"137.74.169.241", -1},
        {"138.197.189.226", -1},
        {"139.99.96.114", -1},
        {"139.99.98.191", -1},
        {"139.99.103.82", -1},
        {"139.99.130.178", -1},
        {"139.99.173.172", -1},
        {"139.162.10.72", -1},
        {"139.162.16.13", -1},
        {"139.162.60.219", -1},
        {"139.162.62.105", -1},
        {"139.162.144.133", -1},
        {"139.162.226.245", -1},
        {"139.162.243.12", -1},
        {"141.255.162.34", -1},
        {"141.255.162.35", -1},
        {"141.255.162.36", -1},
        {"141.255.162.38", -1},
        {"142.4.211.52", -1},
        {"142.44.232.97", -1},
        {"142.44.232.98", -1},
        {"142.44.232.99", -1},
        {"142.44.232.101", -1},
        {"142.44.232.102", -1},
        {"142.44.232.103", -1},
        {"142.44.232.107", -1},
        {"142.44.232.114", -1},
        {"142.44.232.116", -1},
        {"144.217.56.145", -1},
        {"144.217.60.211", -1},
        {"144.217.60.239", -1},
        {"144.217.64.46", -1},
        {"144.217.80.80", -1},
        {"144.217.161.119", -1},
        {"145.239.90.27", -1},
        {"145.239.91.37", -1},
        {"145.239.93.33", -1},
        {"146.185.253.122", -1},
        {"149.36.64.8", -1},
        {"149.202.170.60", -1},
        {"149.202.238.204", -1},
        {"154.127.60.92", -1},
        {"158.69.37.14", -1},
        {"158.69.192.200", -1},
        {"158.69.192.239", -1},
        {"158.69.193.32", -1},
        {"158.69.201.47", -1},
        {"160.119.249.24", -1},
        {"160.119.249.239", -1},
        {"160.202.162.186", -1},
        {"160.202.163.46", -1},
        {"162.213.3.221", -1},
        {"162.247.74.7", -1},
        {"162.247.74.27", -1},
        {"162.247.74.74", -1},
        {"162.247.74.199", -1},
        {"162.247.74.200", -1},
        {"162.247.74.201", -1},
        {"162.247.74.202", -1},
        {"162.247.74.204", -1},
        {"162.247.74.206", -1},
        {"162.247.74.213", -1},
        {"162.247.74.216", -1},
        {"162.247.74.217", -1},
        {"163.47.119.174", -1},
        {"163.172.41.228", -1},
        {"163.172.67.180", -1},
        {"163.172.132.199", -1},
        {"163.172.151.47", -1},
        {"163.172.160.182", -1},
        {"163.172.174.24", -1},
        {"163.172.175.43", -1},
        {"163.172.223.132", -1},
        {"164.77.133.220", -1},
        {"164.132.9.199", -1},
        {"164.132.51.91", -1},
        {"164.132.106.162", -1},
        {"166.70.15.14", -1},
        {"166.70.207.2", -1},
        {"167.99.42.89", -1},
        {"167.114.34.150", -1},
        {"167.114.155.99", -1},
        {"171.25.193.20", -1},
        {"171.25.193.25", -1},
        {"171.25.193.77", -1},
        {"171.25.193.78", -1},
        {"171.25.193.235", -1},
        {"171.50.157.39", -1},
        {"172.98.193.43", -1},
        {"172.103.94.91", -1},
        {"172.104.176.43", -1},
        {"172.221.207.95", -1},
        {"173.14.173.227", -1},
        {"173.79.149.245", -1},
        {"173.212.244.116", -1},
        {"173.249.48.78", -1},
        {"173.249.57.253", -1},
        {"173.255.226.142", -1},
        {"176.8.24.64", -1},
        {"176.10.99.200", -1},
        {"176.10.104.240", -1},
        {"176.31.45.3", -1},
        {"176.31.180.157", -1},
        {"176.31.208.193", -1},
        {"176.53.90.26", -1},
        {"176.58.89.182", -1},
        {"176.58.100.98", -1},
        {"176.107.179.147", -1},
        {"176.119.28.57", -1},
        {"176.123.26.14", -1},
        {"176.123.26.17", -1},
        {"176.126.70.240", -1},
        {"176.126.252.11", -1},
        {"176.126.252.12", -1},
        {"177.18.195.1", -1},
        {"177.99.128.37", -1},
        {"177.133.182.35", -1},
        {"177.205.177.25", -1},
        {"178.6.80.213", -1},
        {"178.17.166.146", -1},
        {"178.17.166.147", -1},
        {"178.17.166.148", -1},
        {"178.17.166.149", -1},
        {"178.17.170.13", -1},
        {"178.17.170.81", -1},
        {"178.17.170.135", -1},
        {"178.17.170.156", -1},
        {"178.17.170.164", -1},
        {"178.17.170.194", -1},
        {"178.17.170.196", -1},
        {"178.17.171.102", -1},
        {"178.17.171.114", -1},
        {"178.17.171.214", -1},
        {"178.17.174.10", -1},
        {"178.17.174.14", -1},
        {"178.17.174.196", -1},
        {"178.17.174.198", -1},
        {"178.17.174.200", -1},
        {"178.17.174.232", -1},
        {"178.18.83.215", -1},
        {"178.20.55.16", -1},
        {"178.20.55.18", -1},
        {"178.32.147.150", -1},
        {"178.32.181.97", -1},
        {"178.32.181.98", -1},
        {"178.32.181.99", -1},
        {"178.32.185.97", -1},
        {"178.32.185.98", -1},
        {"178.32.185.102", -1},
        {"178.165.72.177", -1},
        {"178.175.129.90", -1},
        {"178.175.129.91", -1},
        {"178.175.131.194", -1},
        {"178.175.135.99", -1},
        {"178.175.135.100", -1},
        {"178.175.135.101", -1},
        {"178.175.135.102", -1},
        {"178.175.139.122", -1},
        {"178.175.148.224", -1},
        {"178.238.237.44", -1},
        {"178.239.176.73", -1},
        {"179.176.48.244", -1},
        {"179.178.77.58", -1},
        {"179.183.162.250", -1},
        {"182.64.103.138", -1},
        {"182.77.45.36", -1},
        {"185.10.68.11", -1},
        {"185.10.68.24", -1},
        {"185.10.68.76", -1},
        {"185.10.68.91", -1},
        {"185.10.68.93", -1},
        {"185.10.68.98", -1},
        {"185.10.68.128", -1},
        {"185.10.68.156", -1},
        {"185.10.68.225", -1},
        {"185.14.187.156", -1},
        {"185.34.33.2", -1},
        {"185.62.57.91", -1},
        {"185.62.57.229", -1},
        {"185.65.205.10", -1},
        {"185.66.200.10", -1},
        {"185.72.244.24", -1},
        {"185.80.216.93", -1},
        {"185.82.216.233", -1},
        {"185.83.215.29", -1},
        {"185.83.215.96", -1},
        {"185.94.190.211", -1},
        {"185.100.84.82", -1},
        {"185.100.85.61", -1},
        {"185.100.85.101", -1},
        {"185.100.85.147", -1},
        {"185.100.85.190", -1},
        {"185.100.85.191", -1},
        {"185.100.86.100", -1},
        {"185.100.86.128", -1},
        {"185.100.86.154", -1},
        {"185.100.86.182", -1},
        {"185.100.87.129", -1},
        {"185.100.87.206", -1},
        {"185.100.87.207", -1},
        {"185.104.120.2", -1},
        {"185.104.120.3", -1},
        {"185.104.120.4", -1},
        {"185.104.120.5", -1},
        {"185.104.120.7", -1},
        {"185.104.120.60", -1},
        {"185.107.47.215", -1},
        {"185.107.94.183", -1},
        {"185.107.94.233", -1},
        {"185.112.146.138", -1},
        {"185.113.128.30", -1},
        {"185.117.215.9", -1},
        {"185.125.33.114", -1},
        {"185.125.33.242", -1},
        {"185.127.25.68", -1},
        {"185.129.62.62", -1},
        {"185.129.62.63", -1},
        {"185.147.237.8", -1},
        {"185.165.168.77", -1},
        {"185.165.168.168", -1},
        {"185.165.168.229", -1},
        {"185.165.169.165", -1},
        {"185.169.42.21", -1},
        {"185.174.173.46", -1},
        {"185.175.208.179", -1},
        {"185.175.208.180", -1},
        {"185.193.125.84", -1},
        {"185.193.125.115", -1},
        {"185.200.123.1", -1},
        {"185.200.123.2", -1},
        {"185.200.123.3", -1},
        {"185.200.123.4", -1},
        {"185.200.123.5", -1},
        {"185.200.123.6", -1},
        {"185.200.123.7", -1},
        {"185.200.123.8", -1},
        {"185.200.123.9", -1},
        {"185.200.123.10", -1},
        {"185.200.123.11", -1},
        {"185.200.123.12", -1},
        {"185.200.123.13", -1},
        {"185.200.123.14", -1},
        {"185.200.123.15", -1},
        {"185.200.123.16", -1},
        {"185.200.123.17", -1},
        {"185.200.123.18", -1},
        {"185.200.123.19", -1},
        {"185.200.123.20", -1},
        {"185.217.93.22", -1},
        {"185.220.100.252", -1},
        {"185.220.100.253", -1},
        {"185.220.100.254", -1},
        {"185.220.100.255", -1},
        {"185.220.101.0", -1},
        {"185.220.101.1", -1},
        {"185.220.101.3", -1},
        {"185.220.101.5", -1},
        {"185.220.101.6", -1},
        {"185.220.101.7", -1},
        {"185.220.101.8", -1},
        {"185.220.101.9", -1},
        {"185.220.101.10", -1},
        {"185.220.101.12", -1},
        {"185.220.101.13", -1},
        {"185.220.101.15", -1},
        {"185.220.101.20", -1},
        {"185.220.101.21", -1},
        {"185.220.101.22", -1},
        {"185.220.101.25", -1},
        {"185.220.101.27", -1},
        {"185.220.101.28", -1},
        {"185.220.101.29", -1},
        {"185.220.101.30", -1},
        {"185.220.101.32", -1},
        {"185.220.101.33", -1},
        {"185.220.101.34", -1},
        {"185.220.101.44", -1},
        {"185.220.101.45", -1},
        {"185.220.101.46", -1},
        {"185.220.102.4", -1},
        {"185.220.102.6", -1},
        {"185.220.102.7", -1},
        {"185.220.102.8", -1},
        {"185.222.202.12", -1},
        {"185.222.202.104", -1},
        {"185.222.202.125", -1},
        {"185.227.68.78", -1},
        {"185.227.68.250", -1},
        {"185.227.82.9", -1},
        {"185.248.160.21", -1},
        {"185.248.160.65", -1},
        {"185.248.160.214", -1},
        {"185.248.160.231", -1},
        {"186.149.140.7", -1},
        {"186.214.57.183", -1},
        {"186.214.61.9", -1},
        {"186.214.63.81", -1},
        {"188.65.144.2", -1},
        {"188.116.11.110", -1},
        {"188.166.184.185", -1},
        {"188.214.104.146", -1},
        {"188.235.40.128", -1},
        {"189.78.113.240", -1},
        {"189.84.21.44", -1},
        {"190.10.8.50", -1},
        {"190.162.198.98", -1},
        {"190.210.98.90", -1},
        {"190.216.2.136", -1},
        {"191.32.204.94", -1},
        {"191.250.250.237", -1},
        {"191.251.133.76", -1},
        {"192.3.169.210", -1},
        {"192.34.80.176", -1},
        {"192.42.116.13", -1},
        {"192.42.116.14", -1},
        {"192.42.116.15", -1},
        {"192.42.116.16", -1},
        {"192.42.116.17", -1},
        {"192.42.116.18", -1},
        {"192.42.116.19", -1},
        {"192.42.116.20", -1},
        {"192.42.116.22", -1},
        {"192.42.116.23", -1},
        {"192.42.116.24", -1},
        {"192.42.116.25", -1},
        {"192.42.116.26", -1},
        {"192.42.116.27", -1},
        {"192.42.116.28", -1},
        {"192.99.247.1", -1},
        {"192.160.102.164", -1},
        {"192.160.102.165", -1},
        {"192.160.102.166", -1},
        {"192.160.102.168", -1},
        {"192.160.102.169", -1},
        {"192.160.102.170", -1},
        {"192.195.80.10", -1},
        {"193.29.58.84", -1},
        {"193.90.12.115", -1},
        {"193.90.12.116", -1},
        {"193.90.12.117", -1},
        {"193.90.12.118", -1},
        {"193.90.12.119", -1},
        {"193.104.254.130", -1},
        {"193.107.85.56", -1},
        {"193.107.85.60", -1},
        {"193.107.85.62", -1},
        {"193.110.157.151", -1},
        {"193.138.52.161", -1},
        {"193.169.145.66", -1},
        {"193.169.145.194", -1},
        {"193.169.145.202", -1},
        {"193.171.202.150", -1},
        {"193.201.225.45", -1},
        {"194.99.106.149", -1},
        {"194.187.249.62", -1},
        {"194.187.249.190", -1},
        {"195.91.66.210", -1},
        {"195.91.66.218", -1},
        {"195.123.209.104", -1},
        {"195.123.212.75", -1},
        {"195.123.213.116", -1},
        {"195.123.217.153", -1},
        {"195.123.224.108", -1},
        {"195.123.226.153", -1},
        {"195.123.237.251", -1},
        {"195.135.194.134", -1},
        {"195.154.118.36", -1},
        {"195.176.3.19", -1},
        {"195.176.3.20", -1},
        {"195.176.3.23", -1},
        {"195.176.3.24", -1},
        {"195.228.45.176", -1},
        {"195.254.134.194", -1},
        {"195.254.134.242", -1},
        {"195.254.135.76", -1},
        {"196.41.123.180", -1},
        {"197.206.208.9", -1},
        {"197.231.221.211", -1},
        {"198.40.54.178", -1},
        {"198.50.200.129", -1},
        {"198.50.200.131", -1},
        {"198.50.200.135", -1},
        {"198.58.100.240", -1},
        {"198.58.107.53", -1},
        {"198.73.50.71", -1},
        {"198.96.155.3", -1},
        {"198.98.56.149", -1},
        {"198.98.61.36", -1},
        {"198.167.223.38", -1},
        {"198.211.122.191", -1},
        {"198.255.62.92", -1},
        {"198.255.62.94", -1},
        {"199.68.196.124", -1},
        {"199.87.154.255", -1},
        {"199.127.226.150", -1},
        {"199.195.250.68", -1},
        {"199.195.250.77", -1},
        {"199.249.223.40", -1},
        {"199.249.223.41", -1},
        {"199.249.223.42", -1},
        {"199.249.223.43", -1},
        {"199.249.223.44", -1},
        {"199.249.223.45", -1},
        {"199.249.223.46", -1},
        {"199.249.223.47", -1},
        {"199.249.223.48", -1},
        {"199.249.223.49", -1},
        {"199.249.223.60", -1},
        {"199.249.223.61", -1},
        {"199.249.223.62", -1},
        {"199.249.223.63", -1},
        {"199.249.223.64", -1},
        {"199.249.223.65", -1},
        {"199.249.223.66", -1},
        {"199.249.223.67", -1},
        {"199.249.223.68", -1},
        {"199.249.223.69", -1},
        {"199.249.223.71", -1},
        {"199.249.223.72", -1},
        {"199.249.223.73", -1},
        {"199.249.223.74", -1},
        {"199.249.223.75", -1},
        {"199.249.223.76", -1},
        {"199.249.223.77", -1},
        {"199.249.223.78", -1},
        {"199.249.223.79", -1},
        {"199.249.223.81", -1},
        {"199.249.224.40", -1},
        {"199.249.224.41", -1},
        {"199.249.224.42", -1},
        {"199.249.224.43", -1},
        {"199.249.224.44", -1},
        {"199.249.224.45", -1},
        {"199.249.224.46", -1},
        {"199.249.224.47", -1},
        {"199.249.224.48", -1},
        {"199.249.224.49", -1},
        {"199.249.224.60", -1},
        {"199.249.224.61", -1},
        {"199.249.224.62", -1},
        {"199.249.224.63", -1},
        {"199.249.224.64", -1},
        {"199.249.224.65", -1},
        {"199.249.224.66", -1},
        {"199.249.224.67", -1},
        {"199.249.224.68", -1},
        {"199.249.224.69", -1},
        {"200.98.137.240", -1},
        {"200.98.161.148", -1},
        {"201.80.40.186", -1},
        {"204.8.156.142", -1},
        {"204.11.50.131", -1},
        {"204.12.208.58", -1},
        {"204.17.56.42", -1},
        {"204.85.191.30", -1},
        {"204.85.191.31", -1},
        {"204.194.29.4", -1},
        {"205.168.84.133", -1},
        {"205.185.113.14", -1},
        {"205.185.117.207", -1},
        {"205.185.127.219", -1},
        {"206.81.3.227", -1},
        {"206.248.184.127", -1},
        {"207.180.194.30", -1},
        {"207.244.70.35", -1},
        {"209.126.101.29", -1},
        {"209.141.45.212", -1},
        {"209.141.51.150", -1},
        {"209.141.55.10", -1},
        {"209.141.61.45", -1},
        {"212.16.104.33", -1},
        {"212.19.17.213", -1},
        {"212.21.66.6", -1},
        {"212.47.229.60", -1},
        {"212.47.246.21", -1},
        {"212.81.199.159", -1},
        {"212.92.219.15", -1},
        {"212.237.18.141", -1},
        {"213.39.169.160", -1},
        {"213.61.215.54", -1},
        {"213.95.149.22", -1},
        {"213.108.105.71", -1},
        {"213.252.140.118", -1},
        {"216.218.134.12", -1},
        {"216.239.90.19", -1},
        {"217.12.221.196", -1},
        {"217.115.10.131", -1},
        {"217.147.169.49", -1},
        {"217.147.169.75", -1},
        {"217.170.197.83", -1},
        {"217.170.197.89", -1},
        {"217.182.78.177", -1},
        {"217.182.168.178", -1},
        {"217.234.128.53", -1},
        {"217.234.130.178", -1},
        {"217.234.130.205", -1},
        {"217.234.131.233", -1},
        {"217.234.132.34", -1},
        {"217.234.132.78", -1},
        {"217.234.133.211", -1},
        {"217.234.133.235", -1},
        {"217.234.134.195", -1},
        {"217.234.136.153", -1},
        {"217.234.137.16", -1},
        {"217.234.137.50", -1},
        {"217.234.137.69", -1},
        {"217.234.140.11", -1},
        {"217.234.140.55", -1},
        {"217.234.141.214", -1},
        {"217.234.141.219", -1},
        {"217.234.142.43", -1},
        {"217.234.142.145", -1},
        {"217.234.142.233", -1},
        {"217.234.145.245", -1},
        {"217.234.146.175", -1},
        {"217.234.146.220", -1},
        {"217.234.149.200", -1},
        {"217.234.150.13", -1},
        {"217.234.150.30", -1},
        {"217.234.151.210", -1},
        {"217.234.152.156", -1},
        {"217.234.153.148", -1},
        {"217.234.153.206", -1},
        {"217.234.154.72", -1},
        {"217.234.155.182", -1},
        {"217.234.157.65", -1},
        {"217.234.157.171", -1},
        {"217.234.157.208", -1},
        {"217.234.158.98", -1},
        {"220.129.57.52", -1},
        {"223.26.48.248", -1}
    };
    
    if (g_tor_exit_ips.count(val) > 0)
    {
        return true;
    }
    
    return false;
}

