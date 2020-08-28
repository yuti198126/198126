#pragma once

#include <fc/crypto/public_key.hpp>
#include <fc/crypto/signature.hpp>
#include <fc/crypto/sha256.hpp>

#include <boost/container/flat_set.hpp>

#include <set>

namespace eosio::tpm {

class tpm_key {
public:
   tpm_key(const std::string& tcti, const fc::crypto::public_key& pubkey, const std::vector<unsigned>& pcrs);
   ~tpm_key();

   fc::crypto::signature sign(const fc::sha256& digest);

private:
   struct impl;
   constexpr static size_t fwd_size = 256;
   fc::fwd<impl,fwd_size> my;
};

boost::container::flat_set<fc::crypto::public_key> get_all_persistent_keys(const std::string& tcti);
fc::crypto::public_key create_key(const std::string& tcti, const std::vector<unsigned>& pcrs);

}