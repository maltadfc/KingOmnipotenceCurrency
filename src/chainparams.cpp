// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"

#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/uniform_01.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

static void MineGenesis(CBlockHeader& genesisBlock, const uint256& powLimit, bool noProduction)
{
    if(noProduction)
        genesisBlock.nTime = std::time(0);
    genesisBlock.nNonce = 0;

    LogPrintf("NOTE: Genesis nTime = %u \n", genesisBlock.nTime);
    LogPrintf("WARN: Genesis nNonce (BLANK!) = %u \n", genesisBlock.nNonce);

    uint256 besthash;
    memset(&besthash,0xFF,32);
    uint256 hashTarget = powLimit;
    LogPrintf("Target: %s\n", hashTarget.GetHex().c_str());
    uint256 newhash = genesisBlock.GetHash();
    while (newhash > hashTarget) {
        genesisBlock.nNonce++;
        if (genesisBlock.nNonce == 0) {
            LogPrintf("NONCE WRAPPED, incrementing time\n");
            ++genesisBlock.nTime;
        }
        // If nothing found after trying for a while, print status
        if ((genesisBlock.nNonce & 0xfff) == 0)
            LogPrintf("nonce %08X: hash = %s (target = %s)\n",
                   genesisBlock.nNonce, newhash.ToString().c_str(),
                   hashTarget.ToString().c_str());

        if(newhash < besthash) {
            besthash = newhash;
            LogPrintf("New best: %s\n", newhash.GetHex().c_str());
        }
        newhash = genesisBlock.GetHash();
    }
    LogPrintf("Genesis nTime = %u \n", genesisBlock.nTime);
    LogPrintf("Genesis nNonce = %u \n", genesisBlock.nNonce);
    LogPrintf("Genesis nBits: %08x\n", genesisBlock.nBits);
    LogPrintf("Genesis Hash = %s\n", newhash.ToString().c_str());
    LogPrintf("Genesis Hash Merkle Root = %s\n", genesisBlock.hashMerkleRoot.ToString().c_str());
}

static const long hextable[] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 10-19
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 30-39
    -1, -1, -1, -1, -1, -1, -1, -1,  0,  1,
     2,  3,  4,  5,  6,  7,  8,  9, -1, -1,         // 50-59
    -1, -1, -1, -1, -1, 10, 11, 12, 13, 14,
    15, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 70-79
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, 10, 11, 12,         // 90-99
    13, 14, 15, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 110-109
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 130-139
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 150-159
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 170-179
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 190-199
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 210-219
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 230-239
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1
};

int64_t CChainParams::GetProofOfWorkReward(int nHeight, int64_t nFees) const
{
    // miner's coin base reward
    int64_t nSubsidy = 0 * COIN;

    if (nHeight == 0)
        nSubsidy = 0 * COIN;
    else if (nHeight == 1)
        nSubsidy = 1200000000 * COIN;
    else
        nSubsidy = 0 * COIN;

    if (fDebug && GetBoolArg("-printcreation"))
        LogPrintf("GetProofOfWorkReward() : create=%s nSubsidy=%d\n", FormatMoney(nSubsidy).c_str(), nSubsidy);

    return nSubsidy + nFees;
};


int static generateMTRandom(unsigned int s, int range)
{
    boost::mt19937 gen(s);
    boost::uniform_int<> dist(1, range);
    return dist(gen);
}

int long hex2long(const char* hexString)
{
    long ret = 0;

    while (*hexString && ret >= 0)
    {
        ret = (ret << 4) | hextable[(uint8_t)*hexString++];
    }

    return ret;
}

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex* pindexPrev, int64_t nCoinAge, int64_t nFees) const
{

    int nHeight = pindexPrev->nHeight;
    int64_t nSubsidy = nCoinAge * 5 * CENT * 33 / (365 * 33 + 8);
    if(nHeight >= 60*24*365*4){
        nSubsidy = nCoinAge * 0.005 * CENT * 33 / (365 * 33 + 8);
    }

    if (fDebug && GetBoolArg("-printcreation"))
        LogPrintf("GetProofOfStakeReward(): create=%s nCoinAge=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge);

    return nSubsidy + nFees;
}

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

// Convert the pnSeeds array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, const unsigned int *data, unsigned int count, int port)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int k = 0; k < count; ++k)
    {
        struct in_addr ip;
        unsigned int i = data[k], t;

        // -- convert to big endian
        t =   (i & 0x000000ff) << 24u
            | (i & 0x0000ff00) << 8u
            | (i & 0x00ff0000) >> 8u
            | (i & 0xff000000) >> 24u;

        memcpy(&ip, &t, sizeof(ip));

        CAddress addr(CService(ip, port));
        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CBaseChainParams : public CChainParams {
public:
    CBaseChainParams() {
        const char* pszTimestamp = "www.cryptocoinsnews.com/news/bitlicense-regulations-forked-github-bitcoin-community/2014/07/19";
        CTransaction txNew;
        txNew.nTime = GENESIS_BLOCK_TIME;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = GENESIS_BLOCK_TIME;

        vSeeds.push_back(CDNSSeedData("KingOmnipotenceCurrency.co1","47.99.90.142"));
        vSeeds.push_back(CDNSSeedData("KingOmnipotenceCurrency.co2","47.107.64.205"));
        vSeeds.push_back(CDNSSeedData("KingOmnipotenceCurrency.co3","47.92.205.7"));

    }
    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual const std::vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    std::vector<CAddress> vFixedSeeds;
};

//#define SHOW_LOG true

class CMainParams : public CBaseChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0xb4;

        vAlertPubKey = ParseHex("031d5def92b2d59943e57aaa8b1adbb110ff215fc4ebdc6fb5c9a797e2b1dea527");

        nDefaultPort = 18824;
        nRPCPort = 18825;
        nBIP44ID = 0x80000023;

        nLastPOWBlock = 31000000;
        nLastFairLaunchBlock = 1000000;

        nFirstPosv2Block = 31000000;
        nFirstPosv3Block = 31000000;

        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16); // "standard" scrypt target limit for proof of work, results with 0,000244140625 proof-of-work difficulty
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 16);
        bnProofOfStakeLimitV2 = CBigNum(~uint256(0) >> 16);

        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 152450;
        hashGenesisBlock = genesis.GetHash();
#ifdef SHOW_LOG
        MineGenesis(genesis,bnProofOfWorkLimit.getuint256(),false);
        LogPrintf("genesis.hashGenesisBlock == %s\n", hashGenesisBlock.ToString().c_str());
        LogPrintf("genesis.hashMerkleRoot == %s\n", genesis.hashMerkleRoot.ToString().c_str());
        LogPrintf("genesis.nBits == %d\n", genesis.nBits);
        LogPrintf("genesis.nNonce == %d\n", genesis.nNonce);
#endif
        assert(hashGenesisBlock == uint256("0x0000905a096be7888c74eca2e3b350534fdb1d502c0d07bce105b0f6b8bd0bd7"));
        assert(genesis.hashMerkleRoot == uint256("0x93d0090900344ab326b75d7d05118c05a776fc9a6a869384396ce29c62254603"));

        base58Prefixes[PUBKEY_ADDRESS]      = list_of(46).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS]      = list_of(125).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]          = list_of(191).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[STEALTH_ADDRESS]     = list_of(40).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY]      = list_of(0xEE)(0x80)(0x28)(0x6A).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY]      = list_of(0xEE)(0x80)(0x31)(0xE8).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_KEY_HASH]        = list_of(137).convert_to_container<std::vector<unsigned char> >();         // x
        base58Prefixes[EXT_ACC_HASH]        = list_of(83).convert_to_container<std::vector<unsigned char> >();          // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC]  = list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >(); // xprv
        base58Prefixes[EXT_SECRET_KEY_BTC]  = list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >(); // xpub

        //vSeeds.push_back(CDNSSeedData("123.57.242.74",  "123.57.242.74"));
        //vSeeds.push_back(CDNSSeedData("35.163.60.239",  "35.163.60.239"));
        //vSeeds.push_back(CDNSSeedData("54.250.155.48",  "54.250.155.48"));
        //convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);
    }

    virtual Network NetworkID() const { return CChainParams::MAIN; }
};
static CMainParams mainParams;

//
// Testnet
//

class CTestNetParams : public CBaseChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strDataDir = "testnet";

        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x07;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x05;
        pchMessageStart[3] = 0x0b;

        vAlertPubKey = ParseHex("0373d8dce43eb98374bcfff2352cd559e6774fd6a87eef73b2fbdb39b2b0bc0082");

        nDefaultPort = 51997;
        nRPCPort = 51996;
        nBIP44ID = 0x80000001;

        nLastPOWBlock = 110;
        nLastFairLaunchBlock = 10;

        nFirstPosv2Block = 110;
        nFirstPosv3Block = 500;

        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 20);
        bnProofOfStakeLimitV2 = CBigNum(~uint256(0) >> 16);

        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 152450;
        hashGenesisBlock = genesis.GetHash();
#ifdef SHOW_LOG
        LogPrintf("testnet.hashGenesisBlock == %s\n", hashGenesisBlock.ToString().c_str());
        LogPrintf("testnet.hashMerkleRoot == %s\n", genesis.hashMerkleRoot.ToString().c_str());
        LogPrintf("testnet.nBits == %d\n", genesis.nBits);
        LogPrintf("testnet.nNonce == %d\n", genesis.nNonce);
#endif
        assert(hashGenesisBlock == uint256("0x0000905a096be7888c74eca2e3b350534fdb1d502c0d07bce105b0f6b8bd0bd7"));
        assert(genesis.hashMerkleRoot == uint256("0x93d0090900344ab326b75d7d05118c05a776fc9a6a869384396ce29c62254603"));

        base58Prefixes[PUBKEY_ADDRESS]      = list_of(127).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS]      = list_of(196).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]          = list_of(255).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[STEALTH_ADDRESS]     = list_of(40).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY]      = list_of(0x76)(0xC0)(0xFD)(0xFB).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY]      = list_of(0x76)(0xC1)(0x07)(0x7A).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_KEY_HASH]        = list_of(75).convert_to_container<std::vector<unsigned char> >();          // X
        base58Prefixes[EXT_ACC_HASH]        = list_of(23).convert_to_container<std::vector<unsigned char> >();          // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC]  = list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >(); // tprv
        base58Prefixes[EXT_SECRET_KEY_BTC]  = list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >(); // tpub

        //convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));
        convertSeeds(vFixedSeeds, pnTestnetSeed, ARRAYLEN(pnTestnetSeed), nDefaultPort);
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strDataDir = "regtest";

        nFirstPosv2Block = -1;
        nFirstPosv3Block = -1;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 152450;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
#ifdef SHOW_LOG
        LogPrintf("regtest.hashGenesisBlock == %s\n", hashGenesisBlock.ToString().c_str());
        LogPrintf("regtest.hashMerkleRoot == %s\n", genesis.hashMerkleRoot.ToString().c_str());
        LogPrintf("regtest.nBits == %d\n", genesis.nBits);
        LogPrintf("regtest.nNonce == %d\n", genesis.nNonce);
#endif
        assert(hashGenesisBlock == uint256("0x0000905a096be7888c74eca2e3b350534fdb1d502c0d07bce105b0f6b8bd0bd7"));
        assert(genesis.hashMerkleRoot == uint256("0x93d0090900344ab326b75d7d05118c05a776fc9a6a869384396ce29c62254603"));
        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

const CChainParams &TestNetParams() {
    return testNetParams;
}

const CChainParams &MainNetParams() {
    return mainParams;
}

void SelectParams(CChainParams::Network network)
{
    switch (network)
    {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    };
};

bool SelectParamsFromCommandLine()
{
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
    {
        return false;
    };

    if (fRegTest)
    {
        SelectParams(CChainParams::REGTEST);
    } else
    if (fTestNet)
    {
        SelectParams(CChainParams::TESTNET);
    } else
    {
        SelectParams(CChainParams::MAIN);
    };

    return true;
}
