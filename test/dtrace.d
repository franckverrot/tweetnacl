tweetnacl*:tweetnacl.bundle:m_crypto_box_keypair:method-entry  { printf(" crypto_box_keypair:method-entry [%s:%d]\n", copyinstr(arg0), arg1); }
tweetnacl*:tweetnacl.bundle:m_crypto_box_keypair:method-return { printf("crypto_box_keypair:method-return [%s:%d]\n", copyinstr(arg0), arg1); }
tweetnacl*:tweetnacl.bundle:m_crypto_box:method-entry          { printf("         crypto_box:method-entry [%s:%d]\n", copyinstr(arg0), arg1); }
tweetnacl*:tweetnacl.bundle:m_crypto_box:method-return         { printf("        crypto_box:method-return [%s:%d]\n", copyinstr(arg0), arg1); }
tweetnacl*:tweetnacl.bundle:m_crypto_box_open:method-entry     { printf("    crypto_box_open:method-entry [%s:%d]\n", copyinstr(arg0), arg1); }
tweetnacl*:tweetnacl.bundle:m_crypto_box_open:method-return    { printf("   crypto_box_open:method-return [%s:%d]\n", copyinstr(arg0), arg1); }
