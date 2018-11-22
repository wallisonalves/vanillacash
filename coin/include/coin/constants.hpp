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

#ifndef COIN_CONSTANTS_HPP
#define COIN_CONSTANTS_HPP

#include <cstdint>
#include <string>

#include <coin/big_number.hpp>

/**
 * Enables GUI related function calls.
 */
#define COIN_USE_GUI 1

namespace coin {
namespace constants {

    /**
     * The client version major.
     */
    enum { version_client_major = 0 };
    
    /**
     * The client version minor.
     */
    enum { version_client_minor = 6 };

    /**
     * The client version revision.
     */
    enum { version_client_revision = 0 };
    
    /**
     * The client version build.
     */
    enum { version_client_build = 4 };

    /**
     * The client version.
     */
    static const auto version_client =
        1000000 * version_client_major + 10000 * version_client_minor +
        100 * version_client_revision + 1 * version_client_build
    ;
    
    /**
     * If true the code will operate on the test network configuration.
     */
    static const bool test_net = false;

    /**
     * The version string.
     */
    static const std::string version_string = "0.6.0.4";
    
    /**
     * The name of the coin.
     */
    static const std::string client_name = "Vcash";

    /**
     * A coin.
     */
    static const std::int64_t coin = 1000000;
    
    /**
     * A cent.
     */
    enum { cent = 10000 };
    
    /**
     * The maximum money supply.
     */
    static const std::int64_t max_money_supply = 30735360 * coin;
    
    /**
     * The minimum transaction fee.
     */
    static const std::int64_t min_tx_fee = 0.05 * cent;
    
    /**
     * The minimum relay transaction fee.
     */
    static const std::int64_t min_relay_tx_fee = 0.05 * cent;

    /**
     * The minimum transaction out amount.
     */
    static const std::int64_t min_txout_amount = min_tx_fee;

    /**
     * The chain start time.
     */
    static const std::int64_t chain_start_time = 1419310800;

    /**
     * The number of blocks after which a coin matures.
     */
    enum { coinbase_maturity = 200 };
    
    /**
     * The number of blocks after which a coin matures on a test network.
     */
    enum { coinbase_maturity_test_network = 1 };
    
    /**
     * The initial proof of work limit.
     * 0.0002441
     */
    static big_number proof_of_work_limit(~sha256(0) >> 20);
    
    /**
     * The proof of work limit ceiling.
     * 0.00390625
     */
    static big_number proof_of_work_limit_ceiling(~sha256(0) >> 24);
    
    /**
     * The proof of stake limit.
     */
    static big_number proof_of_stake_limit(~sha256(0) >> 10);
    
    /**
     * The annual interest for proof of stake (0.7%).
     */
    static const std::int64_t max_mint_proof_of_stake = 0.007 * coin;
    
    /**
     * The minimum stake age.
     */
    enum { min_stake_age = 60 * 60 * 8 };

    /**
     * The stake age full weight (365 days).
     */
    enum { max_stake_age = 60 * 60 * 24 * 365 };

    /**
     * The maximum allowed clock drift (two hours).
     */
    enum { max_clock_drift = 2 * 60 * 60 };

    /**
     * Threshold for transaction lock time (Tue Nov 5 00:53:20 1985 UTC).
     */
    static const std::uint64_t locktime_threshold = 500000000;

    /**
     * The work and stake target spacing.
     */
    enum { work_and_stake_target_spacing = 200 };

    /**
     * The proof-of-work cutoff block.
     */
    enum { pow_cutoff_block = 2147483647 - 1 };

} // namespace constants
} // namespace coin

#endif // COIN_CONSTANTS_HPP
