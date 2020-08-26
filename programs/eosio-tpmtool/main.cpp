#include <boost/program_options.hpp>

#include <iostream>

#include <eosio/tpm-helpers/tpm-helpers.hpp>

namespace bpo = boost::program_options;

int main(int argc, char** argv) {
   bpo::options_description cli("eosio-tpmtool command line options");

   bool help = false, list = false, create = false;
   std::string tcti;

   cli.add_options()
      ("help,h", bpo::bool_switch(&help)->default_value(false), "Print this help message and exit.")
      ("list,l", bpo::bool_switch(&list)->default_value(false), "List persistent TPM keys useable for EOSIO.")
      ("create,c", bpo::bool_switch(&create)->default_value(false), "Create Secure Enclave key.")
      ("tcti,T", bpo::value<std::string>()->notifier([&](const std::string& s) {
         tcti = s;
      }), "Specify tcti and tcti options")
      ;
   bpo::variables_map varmap;
   try {
      bpo::store(bpo::parse_command_line(argc, argv, cli), varmap);
      bpo::notify(varmap);
   }
   catch(fc::exception& e) {
      elog("${e}", ("e", e.to_detail_string()));
      return 1;
   }

   if((!list && !create) || help) {
      std::ostream& outs = help ? std::cout : std::cerr;
      outs << "eosio-tpmtool is a helper for listing and creating keys in a TPM" << std::endl << std::endl;
      cli.print(outs);
      return help ? 0 : 1;
   }

   if(!(list ^ create)) {
      std::cerr << "Only one option may be specified to eosio-tpmtool" << std::endl;
      return 1;
   }

//   if(create)
//      std::cout << eosio::secure_enclave::create_key().public_key().to_string() << std::endl;

   if(list)
      for(const auto& k : eosio::tpm::get_all_persistent_keys(tcti))
         std::cout << k.to_string() << std::endl;

   return 0;
}
