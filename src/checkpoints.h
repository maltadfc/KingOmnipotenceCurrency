// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CHECKPOINT_H
#define  BITCOIN_CHECKPOINT_H

#include <map>
#include "net.h"
#include "util.h"

class uint256;
class CBlockIndex;
static const uint256 targetHash = uint256("0x98562aaa8f5b5b5e3d96cf1b7bb060e328ebcf986e034be605aab64476f99aff");
/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    // Returns true if block passes checkpoint checks
    bool CheckHardened(int nHeight, const uint256& hash);

    // Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate();

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex);
    CBlockThinIndex* GetLastCheckpoint(const std::map<uint256, CBlockThinIndex*>& mapBlockThinIndex);

    extern MapCheckpoints mapCheckpoints;
    extern MapCheckpoints mapCheckpointsTestnet;

    const CBlockIndex* AutoSelectSyncCheckpoint();
    const CBlockThinIndex* AutoSelectSyncThinCheckpoint();
    bool CheckSync(int nHeight);
}

#endif
