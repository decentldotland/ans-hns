export async function handle(state, action) {
  const input = action.input;

  if (input.function === "setRecord") {
    const { domain, jwk_n, sig, CNAME, A, AAAA, TXT, MX } = input;

    ContractAssert(CNAME || A || AAAA || TXT || MX, "ERROR_MISSING_ARGUMENTS");

    CNAME ? _validateDnsRecord(CNAME) : void 0;
    A ? _validateDnsRecord(A) : void 0;
    AAAA ? _validateDnsRecord(AAAA) : void 0;
    TXT ? _validateDnsRecord(TXT) : void 0;
    MX ? _validateDnsRecord(MX) : void 0;

    await _verifyArSignature(jwk_n, sig);
    const callerDomain = _normalizeDomain(domain);
    const caller = await _ownerToAddress(jwk_n);
    const ansBalances = await _getAnsBalances();
    const callerIndexAns = ansBalances.findIndex(
      (usr) => usr.address === caller
    );

    ContractAssert(callerIndexAns >= 0, "ERROR_CALLER_NOT_FOUND");
    ContractAssert(
      ansBalances[callerIndexAns].ownedDomains
        .map((domainObject) => domainObject.domain)
        .includes(callerDomain),
      "ERROR_CALLER_NOT_DOMAIN_OWNER"
    );

    const domainInStateIndex = state.records.findIndex(
      (record) => record.domain === callerDomain
    );

    if (domainInStateIndex >= 0) {
      CNAME?.name
        ? state.records[domainInStateIndex].CNAME.push(CNAME)
        : void 0;
      A?.name ? state.records[domainInStateIndex].A.push(A) : void 0;
      AAAA?.name ? state.records[domainInStateIndex].AAAA.push(AAAA) : void 0;
      TXT?.name ? state.records[domainInStateIndex].TXT.push(TXT) : void 0;
      MX?.name ? state.records[domainInStateIndex].MX.push(MX) : void 0;

      return { state };
    }

    state.records.push({
      domain: callerDomain,
      CNAME: CNAME ? [CNAME] : [],
      A: A ? [A] : [],
      AAAA: AAAA ? [AAAA] : [],
      TXT: TXT ? [TXT] : [],
      MX: MX ? [MX] : [],
    });

    return { state };
  }

  if (input.function === "delRecord") {
    const { domain, jwk_n, sig, CNAME, A, AAAA, TXT, MX } = input;

    ContractAssert(CNAME || A || AAAA || TXT || MX, "ERROR_MISSING_ARGUMENTS");

    CNAME ? _validateDnsRecord(CNAME) : void 0;
    A ? _validateDnsRecord(A) : void 0;
    AAAA ? _validateDnsRecord(AAAA) : void 0;
    TXT ? _validateDnsRecord(TXT) : void 0;
    MX ? _validateDnsRecord(MX) : void 0;

    await _verifyArSignature(jwk_n, sig);
    const callerDomain = _normalizeDomain(domain);
    const caller = await _ownerToAddress(jwk_n);
    const ansBalances = await _getAnsBalances();
    const callerIndexAns = ansBalances.findIndex(
      (usr) => usr.address === caller
    );

    ContractAssert(callerIndexAns >= 0, "ERROR_CALLER_NOT_FOUND");
    ContractAssert(
      ansBalances[callerIndexAns].ownedDomains
        .map((domainObject) => domainObject.domain)
        .includes(callerDomain),
      "ERROR_CALLER_NOT_DOMAIN_OWNER"
    );

    const domainInStateIndex = state.records.findIndex(
      (record) => record.domain === callerDomain
    );

    ContractAssert(domainInStateIndex >= 0, "ERROR_DOMAIN_NOT_FOUND");

    if (CNAME?.name) {
      const targetIndex = state.records[domainInStateIndex].CNAME.findIndex(
        (record) => record.name === CNAME?.name
      );
      ContractAssert(targetIndex >= 0, "ERROR_RECORD_NOT_FOUND");
      state.records[domainInStateIndex].CNAME.splice(targetIndex, 1);
    }

    if (A?.name) {
      const targetIndex = state.records[domainInStateIndex].A.findIndex(
        (record) => record.name === A?.name
      );
      ContractAssert(targetIndex >= 0, "ERROR_RECORD_NOT_FOUND");
      state.records[domainInStateIndex].A.splice(targetIndex, 1);
    }

    if (AAAA?.name) {
      const targetIndex = state.records[domainInStateIndex].AAAA.findIndex(
        (record) => record.name === AAAA?.name
      );
      ContractAssert(targetIndex >= 0, "ERROR_RECORD_NOT_FOUND");
      state.records[domainInStateIndex].AAAA.splice(targetIndex, 1);
    }

    if (TXT?.name) {
      const targetIndex = state.records[domainInStateIndex].TXT.findIndex(
        (record) => record.name === TXT?.name
      );
      ContractAssert(targetIndex >= 0, "ERROR_RECORD_NOT_FOUND");
      state.records[domainInStateIndex].TXT.splice(targetIndex, 1);
    }

    if (MX?.name) {
      const targetIndex = state.records[domainInStateIndex].MX.findIndex(
        (record) => record.name === MX?.name
      );
      ContractAssert(targetIndex >= 0, "ERROR_RECORD_NOT_FOUND");
      state.records[domainInStateIndex].MX.splice(targetIndex, 1);
    }

    return { state };
  }

  function _validateAnsDomainSyntax(domain) {
    ContractAssert(/^[a-z0-9]{2,15}$/.test(domain), "ERROR_INVALID_ANS_SYNTAX");
  }

  function _normalizeDomain(domain) {
    const caseFolded = domain.toLowerCase();
    const normalizedDomain = caseFolded.normalize("NFKC");
    _validateAnsDomainSyntax(normalizedDomain);
    return normalizedDomain;
  }

  function _validateArweaveAddress(address) {
    ContractAssert(
      /[a-z0-9_-]{43}/i.test(address),
      "ERROR_INVALID_ARWEAVE_ADDRESS"
    );
  }

  function _validatePubKeySyntax(jwk_n) {
    ContractAssert(
      typeof jwk_n === "string" && jwk_n?.length === 683,
      "ERROR_INVALID_JWK_N_SYNTAX"
    );
  }

  function _validateRecordName(record) {
    ContractAssert(
      Object.prototype.toString.call(record) === "[object String]",
      "ERROR_INVALID_TYPE"
    );
    ContractAssert(record.trim().length, "ERROR_INVALID_STRING_LENGTH");
    ContractAssert(
      record.trim().length === record.length,
      "ERROR_PROVIDE_VALID_DNS_RECORD_NAME"
    );
  }

  async function _ownerToAddress(pubkey) {
    try {
      const req = await EXM.deterministicFetch(
        `${state.ar_molecule}/${pubkey}`
      );
      const address = req.asJSON()?.address;
      _validateArweaveAddress(address);
      return address;
    } catch (error) {
      throw new ContractError("ERROR_MOLECULE_SERVER_ERROR");
    }
  }

  async function _verifyArSignature(owner, signature) {
    try {
      _validatePubKeySyntax(owner);

      const encodedMessage = new TextEncoder().encode(state.sig_message);
      const typedArraySig = Uint8Array.from(atob(signature), (c) =>
        c.charCodeAt(0)
      );
      const isValid = await SmartWeave.arweave.crypto.verify(
        owner,
        encodedMessage,
        typedArraySig
      );

      ContractAssert(isValid, "ERROR_INVALID_CALLER_SIGNATURE");
      ContractAssert(
        !state.signatures.includes(signature),
        "ERROR_SIGNATURE_ALREADY_USED"
      );
      state.signatures.push(signature);
    } catch (error) {
      throw new ContractError("ERROR_INVALID_CALLER_SIGNATURE");
    }
  }

  async function _getAnsBalances() {
    try {
      const req = await EXM.deterministicFetch(
        `https://api.exm.dev/read/${state.ans_contract_address}`
      );
      return req.asJSON().balances;
    } catch (error) {
      throw new ContractError("ERROR_EXM_FETCH_REQUEST");
    }
  }

  function _validateDnsRecord(object) {
    _validateRecordName(object.name);
    _validateRecordName(object.value);
  }
}