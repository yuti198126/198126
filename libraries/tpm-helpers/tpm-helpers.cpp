#include <eosio/tpm-helpers/tpm-helpers.hpp>
#include <fc/scoped_exit.hpp>
#include <fc/fwd_impl.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>

extern "C" {
#include <tss2_esys.h>
#include <tss2_rc.h>
#include <tss2_mu.h>
#include <tss2_tctildr.h>
}

namespace eosio::tpm {

static const TPM2B_PUBLIC primary_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (  TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT
                              |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT
                              |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH
                             ),
        .authPolicy = {
            .size = 0,
            .buffer = {0},
        },
        .parameters.rsaDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_AES,
                .keyBits.aes = 128,
                .mode.aes = TPM2_ALG_CFB,
            },
            .scheme = {
                .scheme = TPM2_ALG_NULL,
            },
            .keyBits = 2048,
            .exponent = 0,
        },
        .unique.rsa = {
            .size = 0,
            .buffer = {},
        }
    }
};

static const TPM2B_PUBLIC ecc_sign = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (  TPMA_OBJECT_SIGN_ENCRYPT
                              |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT
                              |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH
                             ),
        .parameters.eccDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_NULL,
                .keyBits.aes = 0,
                .mode.aes = TPM2_ALG_NULL,
            },
            .scheme = {
                .scheme = TPM2_ALG_NULL,//TPM2_ALG_ECDSA,
                //.details = { .ecdsa = { .hashAlg = TPM2_ALG_SHA256 }},
            },
            .curveID = TPM2_ECC_NIST_P256,
            .kdf = { .scheme = TPM2_ALG_NULL, .details = {} }
        },
    }
};

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

TPML_PCR_SELECTION pcr_selection_for_pcrs(const std::vector<unsigned>& pcrs) {
   constexpr unsigned max_pcr_value = 23u;  ///maybe query this from the TPM? at least simulator is angry if too large
   TPML_PCR_SELECTION pcr_selection = {1u, {{TPM2_ALG_SHA256, (max_pcr_value+7)/8}}};
   FC_ASSERT(pcrs.size() < 8, "Max number of PCRs is 8");
   for(const unsigned& pcr : pcrs) {
      FC_ASSERT(pcr <= max_pcr_value, "PCR value must be less than or equal to ${m}", ("m",max_pcr_value));
      pcr_selection.pcrSelections[0].pcrSelect[pcr/8u] |= (1u<<(pcr%8u));
   }
   return pcr_selection;
}

fc::sha256 current_pcr_hash_for_pcrs(esys_context& esys_ctx, const TPML_PCR_SELECTION& pcr_selection) {
   UINT32 pcr_update_counter;
   TPML_DIGEST* pcr_digests;

   TSS2_RC rc = Esys_PCR_Read(esys_ctx.ctx(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pcr_selection, &pcr_update_counter, NULL, &pcr_digests);
   FC_ASSERT(!rc, "Failed to read current PCR digests: ${m}", ("m", Tss2_RC_Decode(rc)));
   auto cleanup_pcr_digests = fc::make_scoped_exit([&]() {free(pcr_digests);});

   fc::sha256::encoder enc;
   for(unsigned i = 0; i < pcr_digests->count; ++i)
      enc.write((const char*)pcr_digests->digests[i].buffer, pcr_digests->digests[i].size);
   return enc.result();
}

class session_with_pcr_policy {
public:
   session_with_pcr_policy(esys_context& esys_ctx, const std::vector<unsigned>& pcrs, bool trial = false) : esys_ctx(esys_ctx) {
      TSS2_RC rc;

      TPMT_SYM_DEF symmetric = {TPM2_ALG_NULL};
      rc = Esys_StartAuthSession(esys_ctx.ctx(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL,
                                 trial ? TPM2_SE_TRIAL : TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &session_handle);
      FC_ASSERT(!rc, "Failed to create TPM auth session: ${m}", ("m", Tss2_RC_Decode(rc)));
      auto cleanup_auth_session = fc::make_scoped_exit([&]() {Esys_FlushContext(esys_ctx.ctx(), session_handle);});

      TPM2B_DIGEST pcr_digest = {sizeof(fc::sha256)};
      TPML_PCR_SELECTION pcr_selection = pcr_selection_for_pcrs(pcrs);
      fc::sha256 read_pcr_digest = current_pcr_hash_for_pcrs(esys_ctx, pcr_selection);
      memcpy(pcr_digest.buffer, read_pcr_digest.data(), sizeof(fc::sha256));

      rc = Esys_PolicyPCR(esys_ctx.ctx(), session_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pcr_digest, &pcr_selection);
      FC_ASSERT(!rc, "Failed to set PCR policy on session: ${m}", ("m", Tss2_RC_Decode(rc)));

      cleanup_auth_session.cancel();
   }

   fc::sha256 policy_digest() {
      TPM2B_DIGEST* policy_digest;
      TSS2_RC rc = Esys_PolicyGetDigest(esys_ctx.ctx(), session_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policy_digest);
      FC_ASSERT(!rc, "Failed to get policy digest: ${m}", ("m", Tss2_RC_Decode(rc)));
      auto cleanup_policy_digest = fc::make_scoped_exit([&]() {free(policy_digest);});
      FC_ASSERT(policy_digest->size == sizeof(fc::sha256), "policy digest size isn't expected");

      return fc::sha256((const char*)policy_digest->buffer, policy_digest->size);
   }

   ~session_with_pcr_policy() {
      Esys_FlushContext(esys_ctx.ctx(), session_handle);
   }

   ESYS_TR session() const {return session_handle;}

private:
   esys_context& esys_ctx;
   ESYS_TR session_handle;
};

fc::crypto::public_key tpm_pub_to_pub(const TPM2B_PUBLIC* tpm_pub) {
   FC_ASSERT(tpm_pub->publicArea.type == TPM2_ALG_ECC, "Not an ECC key");
   FC_ASSERT(tpm_pub->publicArea.parameters.eccDetail.curveID == TPM2_ECC_NIST_P256, "ECC key is not p256 curve");
   FC_ASSERT(tpm_pub->publicArea.unique.ecc.x.size == 32 && tpm_pub->publicArea.unique.ecc.y.size == 32, "p256 key points not expected size");

   fc::crypto::public_key key;
   char serialized_public_key[1 + sizeof(fc::crypto::r1::public_key_data)] = {fc::get_index<fc::crypto::public_key::storage_type, fc::crypto::r1::public_key_shim>()};
   memcpy(serialized_public_key + 2, tpm_pub->publicArea.unique.ecc.x.buffer, 32);
   serialized_public_key[1] = 0x02u + (tpm_pub->publicArea.unique.ecc.y.buffer[31] & 1u);

   fc::datastream<const char*> ds(serialized_public_key, sizeof(serialized_public_key));
   fc::raw::unpack(ds, key);

   return key;
}

std::set<TPM2_HANDLE> persistent_handles(esys_context& esys_ctx) {
   TPMI_YES_NO more_data;
   TSS2_RC rc;
   std::set<TPM2_HANDLE> handles;

   do {
      TPMS_CAPABILITY_DATA* capability_data = nullptr;
      rc = Esys_GetCapability(esys_ctx.ctx(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_CC - handles.size(), &more_data, &capability_data);
      FC_ASSERT(!rc, "Failed to query persistent handles: ${m}", ("m", Tss2_RC_Decode(rc)));
      auto cleanup_capability_data = fc::make_scoped_exit([&]() {free(capability_data);});

      FC_ASSERT(capability_data->capability == TPM2_CAP_HANDLES, "TPM returned non-handle reply");

      for(unsigned i = 0; i < capability_data->data.handles.count; ++i)
         handles.emplace(capability_data->data.handles.handle[i]);
   } while(more_data);

   return handles;
}

std::map<fc::crypto::public_key, TPM2_HANDLE> usable_persistent_keys_and_handles(esys_context& esys_ctx) {
   std::map<fc::crypto::public_key, TPM2_HANDLE> ret;
   TSS2_RC rc;

   for(const TPM2_HANDLE& handle : persistent_handles(esys_ctx)) {
      ESYS_TR object;
      rc = Esys_TR_FromTPMPublic(esys_ctx.ctx(), handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &object);
      if(rc) {
         wlog("Failed to load TPM persistent handle: ${m}", ("m", Tss2_RC_Decode(rc)));
         continue;
      }
      auto cleanup_tr_object = fc::make_scoped_exit([&]() {Esys_TR_Close(esys_ctx.ctx(), &object);});

      TPM2B_PUBLIC* pub = nullptr;
      //TPM2B_NAME* name = nullptr;
      //TPM2B_NAME* qualified_name = nullptr;
      auto cleanup_output = fc::make_scoped_exit([&]() {free(pub); /*free(name); free(qualified_name);*/});

      rc = Esys_ReadPublic(esys_ctx.ctx(), object, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pub, /*&name, &qualified_name*/NULL, NULL);
      if(rc)
         continue;
      if((pub->publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT) == 0)
         continue;
      if(pub->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED)
         continue;

      try {
         ret[tpm_pub_to_pub(pub)] = handle;
      } catch(...) {}
   }

   return ret;
}

struct tpm_key::impl {
   impl(const std::string& tcti, const fc::crypto::public_key& pubkey, const std::vector<unsigned>& pcrs) : pubkey(pubkey), esys_ctx(tcti), pcrs(pcrs) {}

   ~impl() {
      if(key_object != ESYS_TR_NONE)
         Esys_TR_Close(esys_ctx.ctx(), &key_object);
   }

   ESYS_TR key_object = ESYS_TR_NONE;
   fc::ec_key sslkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
   fc::crypto::public_key pubkey;
   esys_context esys_ctx;
   std::vector<unsigned> pcrs;
};

tpm_key::tpm_key(const std::string& tcti, const fc::crypto::public_key& pubkey, const std::vector<unsigned>& pcrs) : my(tcti, pubkey, pcrs) {
   std::map<fc::crypto::public_key, TPM2_HANDLE> keys = usable_persistent_keys_and_handles(my->esys_ctx);
   FC_ASSERT(keys.find(pubkey) != keys.end(), "Unable to find persistent key ${k} in TPM via tcti ${t}", ("k", pubkey)("t", tcti));

   TSS2_RC rc = Esys_TR_FromTPMPublic(my->esys_ctx.ctx(), keys.find(pubkey)->second, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &my->key_object);
   FC_ASSERT(!rc, "Failed to get handle to key ${k}: ${m}", ("k", pubkey)("m", Tss2_RC_Decode(rc)));
}

tpm_key::~tpm_key() = default;

fc::crypto::signature tpm_key::sign(const fc::sha256& digest) {
   TPM2B_DIGEST d = {sizeof(fc::sha256)};
   memcpy(d.buffer, digest.data(), sizeof(fc::sha256));
   TPMT_SIG_SCHEME scheme = {TPM2_ALG_ECDSA};
   scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
   TPMT_TK_HASHCHECK validation = {TPM2_ST_HASHCHECK, TPM2_RH_NULL};

   std::optional<session_with_pcr_policy> session;
   if(my->pcrs.size())
      session.emplace(my->esys_ctx, my->pcrs);

   TPMT_SIGNATURE* sig;
   TSS2_RC rc = Esys_Sign(my->esys_ctx.ctx(), my->key_object, session ? session->session() : ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &d, &scheme, &validation, &sig);
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


fc::crypto::public_key create_key(const std::string& tcti, const std::vector<unsigned>& pcrs) {
   esys_context esys_ctx(tcti);

   TSS2_RC rc;
   TPM2B_SENSITIVE_CREATE empty_sensitive_create = {};
   TPM2B_DATA data = {};
   TPML_PCR_SELECTION pcr_selection = {};

   ESYS_TR primary_handle;
   ESYS_TR created_handle;
   TPM2B_PUBLIC* created_pub;

   TPM2B_PUBLIC key_creation_template = ecc_sign;

   rc = Esys_CreatePrimary(esys_ctx.ctx(), ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &empty_sensitive_create, &primary_template, &data, &pcr_selection,
                                   &primary_handle, NULL, NULL, NULL, NULL);
   FC_ASSERT(!rc, "Failed to create TPM primary key: ${m}", ("m", Tss2_RC_Decode(rc)));

   {
      auto cleanup_primary = fc::make_scoped_exit([&]() {Esys_FlushContext(esys_ctx.ctx(), primary_handle);});

      if(pcrs.size()) {
         session_with_pcr_policy trial_policy_session(esys_ctx, pcrs, true);
         key_creation_template.publicArea.authPolicy.size = sizeof(fc::sha256);
         memcpy(key_creation_template.publicArea.authPolicy.buffer, trial_policy_session.policy_digest().data(), sizeof(fc::sha256));
         key_creation_template.publicArea.objectAttributes &= ~TPMA_OBJECT_USERWITHAUTH;
      }

      size_t offset = 0;
      TPM2B_TEMPLATE templ = { .size = 0 };
      rc = Tss2_MU_TPMT_PUBLIC_Marshal(&key_creation_template.publicArea, templ.buffer, sizeof(templ.buffer), &offset);
      FC_ASSERT(!rc, "Failed to serialize public template: ${m}", ("m", Tss2_RC_Decode(rc)));
      templ.size = offset;

      rc = Esys_CreateLoaded(esys_ctx.ctx(), primary_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                       &empty_sensitive_create, &templ, &created_handle, NULL, &created_pub);
      FC_ASSERT(!rc, "Failed to create key: ${m}", ("m", Tss2_RC_Decode(rc)));
   }
   auto cleanup_created_pub = fc::make_scoped_exit([&]() {free(created_pub);});
   auto cleanup_created_handle = fc::make_scoped_exit([&]() {Esys_FlushContext(esys_ctx.ctx(), created_handle);});

   std::set<TPM2_HANDLE> currrent_persistent_handles = persistent_handles(esys_ctx);
   TPMI_DH_PERSISTENT persistent_handle_id = TPM2_PERSISTENT_FIRST;
   const TPMI_DH_PERSISTENT past_last_owner_persistent = TPM2_PLATFORM_PERSISTENT;
   for(; persistent_handle_id < past_last_owner_persistent; persistent_handle_id++)
      if(currrent_persistent_handles.find(persistent_handle_id) == currrent_persistent_handles.end())
         break;
   FC_ASSERT(persistent_handle_id != past_last_owner_persistent, "Couldn't find unused persistent handle");

   ESYS_TR persistent_handle;
   rc = Esys_EvictControl(esys_ctx.ctx(), ESYS_TR_RH_OWNER, created_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
         persistent_handle_id, &persistent_handle);
   FC_ASSERT(!rc, "Failed to persist TPM key: ${m}", ("m", Tss2_RC_Decode(rc)));
   Esys_TR_Close(esys_ctx.ctx(), &persistent_handle);

   return tpm_pub_to_pub(created_pub);
}

}