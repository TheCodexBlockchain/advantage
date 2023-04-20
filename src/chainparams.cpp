// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The PIVX developers
// Copyright (c) 2021-2022 The DECENOMY Core Developers
// Copyright (c) 2023-2023 The itcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.



/*
  _   _                    _
 (_) | |                  (_)
  _  | |_    ___    ___    _   _ __
 | | | __|  / __|  / _ \  | | | '_ \
 | | | |_  | (__  | (_) | | | | | | |
 |_|  \__|  \___|  \___/  |_| |_| |_|

  _     _            _        _           _
 | |__ | | ___   ___| | _____| |__   __ _(_)_ __
 | '_ \| |/ _ \ / __| |/ / __| '_ \ / _` | | '_ \
 | |_) | | (_) | (__|   < (__| | | | (_| | | | | |
 |_.__/|_|\___/ \___|_|\_\___|_| |_|\__,_|_|_| |_|

*/


#include "chainparams.h"

#include "chainparamsseeds.h"
#include "consensus/merkle.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/assign/list_of.hpp>

#include <assert.h>

#define DISABLED 0x7FFFFFFE;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "itcoin has come online March 2023";
    const CScript genesisOutputScript = CScript() << ParseHex("04bebf0355691b1bfd8d870feeff7922c806c6929f403ced717be464a3f72b91100fff1b6ea6a93eab740a2a505670bc32bc938643da16361743cb0861ca2305c6") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}


/**
  __  __           _                          _
 |  \/  |   __ _  (_)  _ __    _ __     ___  | |_
 | |\/| |  / _` | | | | '_ \  | '_ \   / _ \ | __|
 | |  | | | (_| | | | | | | | | | | | |  __/ | |_
 |_|  |_|  \__,_| |_| |_| |_| |_| |_|  \___|  \__|

 */

static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256("0x000009b39bb66a715cd607f03edc9a11266c2093cc041208a0db6055de50de4a")) // Genesis
    (50, uint256("0x000000b83c4a42db899e5d3692e458d1b62e2fb6a898ca94f041ecc613bffb3b"))
    (100, uint256("0x000000f032022858b638d9e2e385921cdbdd3c78ab2dbb52f8a2a85ab9d12a74"))
    (101, uint256("0x8d9ad16118c3e7eb935a0d862f7d995149110eab609f51d505279d5e773fd0f5"))
    (300, uint256("0x6815bdb9c69fdff58b48b14371f418b34d9c97ca6c16eab60cac3f0bc3cc7977"))
    (600, uint256("0x73978ccfeeb10db39dc672bdac2b4d22f1cd338e854262481dbc791bb4d68831"));

static const Checkpoints::CCheckpointData data =
	{ &mapCheckpoints, 1682001825, 1101, 1440 };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
    (0, uint256S("0x000006215453a491a8399669a0b85b159c2e5b96dc9ddcb67e12f04cbc952f11"));

static const Checkpoints::CCheckpointData dataTestnet =
	{ &mapCheckpoints, 1679841112, 0, 0 };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256S("0x0"));

static const Checkpoints::CCheckpointData dataRegtest =
	{ &mapCheckpoints, 1679841113, 0, 0 };

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";

        genesis = CreateGenesisBlock(1679841111, 292899, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000009b39bb66a715cd607f03edc9a11266c2093cc041208a0db6055de50de4a"));
        assert(genesis.hashMerkleRoot == uint256S("0xb5a80f37a095330b1cbc83b64a56167deb1af949fcf80e38d562d2fef3f1fb05"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 3;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMaxMoneyOut = 46000000000 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nStakeMinAge = 1 * 60 * 60;
        consensus.nStakeMinDepth = 20;
        consensus.nStakeMinDepthV2 = 20;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        // spork keys
        consensus.strSporkPubKey = "0272bff0e938c7a60fb910ff9b91c60523deb7f7b750804484a9af82df1e7460b6";
        consensus.strSporkPubKeyOld = "";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // burn addresses
        consensus.mBurnAddresses = {
           //{ "7XXXXXXXXXXXXXXXXXXXXXXXXXXXaqpZch", 0 }
        };

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                   = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight              = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                    = 101;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                 = 101;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                  = 101;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight      = 101;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight       = 101;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight = 101;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].nActivationHeight     = 101;
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].nActivationHeight     = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_POS].hashActivationBlock                    = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].hashActivationBlock                 = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock                  = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].hashActivationBlock      = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].hashActivationBlock       = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].hashActivationBlock = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].hashActivationBlock     = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].hashActivationBlock     = uint256S("0x0");

        // Treasury
        consensus.nTreasuryActivationHeight = 2;
        consensus.nTreasuryPercentage = 23;
        consensus.strTreasuryAddress = "iEz5k1Frk4oTLr5QSFmdyRxawdBZcQyRMT";

        pchMessageStart[0] = 0xf4;
        pchMessageStart[1] = 0xf4;
        pchMessageStart[2] = 0xf4;
        pchMessageStart[3] = 0xf4;
        nDefaultPort = __PORT_MAINNET__;

        vSeeds.push_back(CDNSSeedData("seeder1", "seed01.getitcoin.com"));
        vSeeds.push_back(CDNSSeedData("seeder2", "seed02.getitcoin.com"));
        vSeeds.push_back(CDNSSeedData("seeder3", "seed03.getitcoin.com"));
        vSeeds.push_back(CDNSSeedData("seeder4", "seed04.getitcoin.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 102);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 103);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 143);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x73).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x1d)(0xfc).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        //convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main)); // added
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }

};
static CMainParams mainParams;



/**
  _____                _                    _
 |_   _|   ___   ___  | |_   _ __     ___  | |_
   | |    / _ \ / __| | __| | '_ \   / _ \ | __|
   | |   |  __/ \__ \ | |_  | | | | |  __/ | |_
   |_|    \___| |___/  \__| |_| |_|  \___|  \__|

 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";

        genesis = CreateGenesisBlock(1679841112, 419920, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000006215453a491a8399669a0b85b159c2e5b96dc9ddcb67e12f04cbc952f11"));
        assert(genesis.hashMerkleRoot == uint256S("0xb5a80f37a095330b1cbc83b64a56167deb1af949fcf80e38d562d2fef3f1fb05"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 12;   // itcoin starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 3;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMaxMoneyOut = INT_MAX * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinDepthV2 = 200;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        // spork keys
        consensus.strSporkPubKey = "04874126a474306e545c88ee11207caf7f5c9481e57327598d4391cce0b833cb7e05f1f038f088220cca329cd73acb22a42e5ec487db96d106741519f60707aa91";
        consensus.strSporkPubKeyOld = "";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                      = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight                 = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                       = 51;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                    = 101;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                     = 101;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight         = 201;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight          = 301;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight    = 401;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].nActivationHeight        = 501;

        consensus.vUpgrades[Consensus::UPGRADE_POS].hashActivationBlock                     = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].hashActivationBlock                  = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock                   = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].hashActivationBlock       = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].hashActivationBlock        = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].hashActivationBlock  =uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].hashActivationBlock      = uint256S("0x0");

        // Treasury
        consensus.nTreasuryActivationHeight = 3;
        consensus.nTreasuryPercentage = 23;
        consensus.strTreasuryAddress = "yDnf2UL2bJQZDgjkfJcU1GtnrbJHhCZkdG";


        pchMessageStart[0] = 0xc9;
        pchMessageStart[1] = 0xc9;
        pchMessageStart[2] = 0xc9;
        pchMessageStart[3] = 0xc9;
        nDefaultPort = __PORT_TESTNET__;

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.push_back(CDNSSeedData("tseeder", "xxxxxxx", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet itcoin addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet itcoin script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet itcoin BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet itcoin BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet itcoin BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;



/**
  ____                   _                  _
 |  _ \    ___    __ _  | |_    ___   ___  | |_
 | |_) |  / _ \  / _` | | __|  / _ \ / __| | __|
 |  _ <  |  __/ | (_| | | |_  |  __/ \__ \ | |_
 |_| \_\  \___|  \__, |  \__|  \___| |___/  \__|
                 |___/
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";

        genesis = CreateGenesisBlock(1679841113, 489325, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000002c71690096cd435a4b15de3f8807e06d28d0ef1964afc6eb5becac9a8b6"));
        assert(genesis.hashMerkleRoot == uint256S("0xb5a80f37a095330b1cbc83b64a56167deb1af949fcf80e38d562d2fef3f1fb05"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 12;   // itcoin starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nCoinbaseMaturity = 3;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMaxMoneyOut = 45000000 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nStakeMinAge = 0;
        consensus.nStakeMinDepth = 2;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;

        consensus.strSporkPubKey = "04d6132266be1ab2d83690c306d84cc37cd92443974e29113a64a09ac26743cabaa03ce0ea33d68682e32eabc4c8f7ee3a7b07b21cc7e863fed6d1a50b4f28eb36";
        consensus.strSporkPubKeyOld = "";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                    = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight               = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                     = 251;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                  = 251;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                   = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight       = 251;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight        = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight  = 300;

        // Treasury
        consensus.nTreasuryActivationHeight = 3;
        consensus.nTreasuryPercentage = 23;
        consensus.strTreasuryAddress = "y5nqVrHF3ff2yarcDkQADxVz8TJCnUtyqj";


        pchMessageStart[0] = 0xb0;
        pchMessageStart[1] = 0xb0;
        pchMessageStart[2] = 0xb0;
        pchMessageStart[3] = 0xb0;
        nDefaultPort = __PORT_REGTEST__;

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}
