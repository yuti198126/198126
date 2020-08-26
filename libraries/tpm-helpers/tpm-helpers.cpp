#include <eosio/tpm-helpers/tpm-helpers.hpp>
#include <fc/scoped_exit.hpp>
#include <fc/fwd_impl.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>

#include <tss2_esys.h>
#include <tss2_rc.h>
extern "C" {
#include <tss2_tctildr.h>
}

namespace eosio::tpm {

class esys_context {
public:
   esys_context(const std::string& tcti) {
      TSS2_RC rc;

      if(!tcti.empty()) {
         rc = Tss2_TctiLdr_Initialize(tcti.c_str(), &tcti_ctx);
         FC_ASSERT(!rc, "Failed to initialize tss tcti \"${s}\": ${m}", ("s", tcti)("m", Tss2_RC_Decode(rc)));
      }

      TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
      rc = Esys_Initialize(&esys_ctx, tcti_ctx, &abi_version);
      if(rc) {
         if(tcti_ctx)
            Tss2_TctiLdr_Finalize(&tcti_ctx);
         FC_ASSERT(!rc, "Failed to initialize tss esys: ${m}", ("m", Tss2_RC_Decode(rc)));
      }
   }

   ~esys_context() {
      if(esys_ctx)
         Esys_Finalize(&esys_ctx);
      if(tcti_ctx)
         Tss2_TctiLdr_Finalize(&tcti_ctx);
   }

   ESYS_CONTEXT* ctx() const {
      return esys_ctx;
   }

   esys_context(esys_context&) = delete;
   esys_context& operator=(const esys_context&) = delete;
private:
   TSS2_TCTI_CONTEXT* tcti_ctx = nullptr;
   ESYS_CONTEXT* esys_ctx = nullptr;
};

std::map<fc::crypto::public_key, TPM2_HANDLE> usable_persistent_keys_and_handles(esys_context& esys_ctx) {
   std::map<fc::crypto::public_key, TPM2_HANDLE> ret;
   TPMI_YES_NO more_data;
   TSS2_RC rc;

   std::list<TPM2_HANDLE> handles;

   do {
      TPMS_CAPABILITY_DATA* capability_data = nullptr;
      rc = Esys_GetCapability(esys_ctx.ctx(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_CC - handles.size(), &more_data, &capability_data);
      FC_ASSERT(!rc, "Failed to query persistent handles: ${m}", ("m", Tss2_RC_Decode(rc)));
      auto cleanup_capability_data = fc::make_scoped_exit([&]() {free(capability_data);});

      FC_ASSERT(capability_data->capability == TPM2_CAP_HANDLES, "TPM returned non-handle");

      for(unsigned i = 0; i < capability_data->data.handles.count; ++i)
         handles.push_back(capability_data->data.handles.handle[i]);
   } while(more_data);

   for(const TPM2_HANDLE& handle : handles) {
      ESYS_TR object;
      rc = Esys_TR_FromTPMPublic(esys_ctx.ctx(), handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &object);
      if(rc)
         continue;
      auto cleanup_tr_object = fc::make_scoped_exit([&]() {Esys_TR_Close(esys_ctx.ctx(), &object);});

      TPM2B_PUBLIC* pub = nullptr;
      TPM2B_NAME* name = nullptr;
      TPM2B_NAME* qualified_name = nullptr;
      auto cleanup_output = fc::make_scoped_exit([&]() {free(pub); free(name); free(qualified_name);});

      rc = Esys_ReadPublic(esys_ctx.ctx(), object, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pub, &name, &qualified_name);
      if(rc)
         continue;
      if(pub->publicArea.type != TPM2_ALG_ECC)
         continue;
      if(pub->publicArea.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256)
         continue;
      if((pub->publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT) == 0)
         continue;
      if(pub->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED)
         continue;
      if(pub->publicArea.unique.ecc.x.size != 32 || pub->publicArea.unique.ecc.y.size != 32)
         continue;

      fc::crypto::public_key key;
      char serialized_public_key[1 + sizeof(fc::crypto::r1::public_key_data)] = {fc::get_index<fc::crypto::public_key::storage_type, fc::crypto::r1::public_key_shim>()};
      memcpy(serialized_public_key + 2, pub->publicArea.unique.ecc.x.buffer, 32);
      serialized_public_key[1] = 0x02u + (pub->publicArea.unique.ecc.y.buffer[31] & 1u);

      fc::datastream<const char*> ds(serialized_public_key, sizeof(serialized_public_key));
      fc::raw::unpack(ds, key);

      ret[key] = handle;
   }

   return ret;
}

struct tpm_key::impl {
   impl(const std::string& tcti, const fc::crypto::public_key& pubkey) : pubkey(pubkey), esys_ctx(tcti) {}

   ~impl() {
      if(key_object != ESYS_TR_NONE)
         Esys_TR_Close(esys_ctx.ctx(), &key_object);
   }

   ESYS_TR key_object = ESYS_TR_NONE;
   fc::ec_key sslkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
   fc::crypto::public_key pubkey;
   esys_context esys_ctx;
};

tpm_key::tpm_key(const std::string& tcti, const fc::crypto::public_key& pubkey) : my(tcti, pubkey) {
   std::map<fc::crypto::public_key, TPM2_HANDLE> keys = usable_persistent_keys_and_handles(my->esys_ctx);
   FC_ASSERT(keys.find(pubkey) != keys.end(), "Unable to find persistent key ${k} in TPM via tcti ${t}", ("k", pubkey)("t", tcti));

   TSS2_RC rc = Esys_TR_FromTPMPublic(my->esys_ctx.ctx(), keys.find(pubkey)->second, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &my->key_object);
   FC_ASSERT(!rc, "Failed to get handle to key ${k}: ${m}", ("k", pubkey)("m", Tss2_RC_Decode(rc)));
}

tpm_key::~tpm_key() = default;

fc::crypto::signature tpm_key::sign_digest(const fc::sha256& digest) {
   TPM2B_DIGEST d = {sizeof(fc::sha256)};
   memcpy(d.buffer, digest.data(), sizeof(fc::sha256));
   TPMT_SIG_SCHEME scheme = {TPM2_ALG_ECDSA};
   scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
   TPMT_TK_HASHCHECK validation = {TPM2_ST_HASHCHECK, TPM2_RH_NULL};

   TPMT_SIGNATURE* sig;
   TSS2_RC rc = Esys_Sign(my->esys_ctx.ctx(), my->key_object, /*signingkey_obj_session_handle*/ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &d, &scheme, &validation, &sig);
   FC_ASSERT(!rc, "Failed TPM sign on key ${k}: ${m}", ("k", my->pubkey)("m", Tss2_RC_Decode(rc)));
   auto cleanup_sig = fc::make_scoped_exit([&]() {free(sig);});
   FC_ASSERT(sig->signature.ecdsa.signatureR.size == 32 && sig->signature.ecdsa.signatureS.size == 32, "Signature size from TPM not as expected");

   fc::ecdsa_sig sslsig = ECDSA_SIG_new();
   FC_ASSERT(sslsig.obj, "Failed to ECDSA_SIG_new");
   BIGNUM *r = BN_new(), *s = BN_new();
   FC_ASSERT(BN_bin2bn(sig->signature.ecdsa.signatureR.buffer,32,r) && BN_bin2bn(sig->signature.ecdsa.signatureS.buffer,32,s), "Failed to BN_bin2bn");
   FC_ASSERT(ECDSA_SIG_set0(sslsig, r, s), "Failed to ECDSA_SIG_set0");


   char serialized_signature[sizeof(fc::crypto::r1::compact_signature) + 1] = {fc::get_index<fc::crypto::signature::storage_type, fc::crypto::r1::signature_shim>()};

   fc::crypto::r1::compact_signature* compact_sig = (fc::crypto::r1::compact_signature*)(serialized_signature + 1);
   *compact_sig = fc::crypto::r1::signature_from_ecdsa(my->sslkey, std::get<fc::crypto::r1::public_key_shim>(my->pubkey._storage)._data, sslsig, digest);

   fc::crypto::signature final_signature;
   fc::datastream<const char*> ds(serialized_signature, sizeof(serialized_signature));
   fc::raw::unpack(ds, final_signature);
   return final_signature;
}

boost::container::flat_set<fc::crypto::public_key> get_all_persistent_keys(const std::string& tcti) {
   esys_context esys_ctx(tcti);

   boost::container::flat_set<fc::crypto::public_key> keys;
   boost::copy(usable_persistent_keys_and_handles(esys_ctx) | boost::adaptors::map_keys, std::inserter(keys, keys.end()));
   return keys;
}

}