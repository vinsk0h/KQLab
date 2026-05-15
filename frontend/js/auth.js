function _ab2b64url(ab) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(ab)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function _b64url2ab(b64) {
  var s = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  var bin = atob(s);
  var buf = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

var Auth = {
  async register(login, password, displayName) {
    var resp = await API.post("/auth/register", { login: login, password: password, displayName: displayName || login });
    if (resp.error) throw new Error(resp.error);
    return { user: resp.user };
  },

  async login(login, password) {
    var resp = await API.post("/auth/login", { login: login, password: password });
    if (resp.error) throw new Error(resp.error);
    return { user: resp.user, must_change_password: resp.must_change_password };
  },

  async demo() {
    var resp = await API.post("/auth/demo", {});
    if (resp.error) throw new Error(resp.error);
    return { user: resp.user };
  },

  async changePassword(currentPassword, newPassword) {
    var resp = await API.post("/auth/change-password", {
      current_password: currentPassword,
      new_password: newPassword,
    });
    if (resp.error) throw new Error(resp.error);
    return resp;
  },

  async me() {
    var resp = await API.get("/auth/me");
    if (!resp || resp.error) return null;
    return resp.user || null;
  },

  async logout() {
    await API.post("/auth/logout", {});
    window.location.reload();
  },

  async addPasskey(userLogin) {
    var resp = await API.post("/auth/passkey/challenge", {});
    if (resp.error) throw new Error(resp.error);

    var cred = await navigator.credentials.create({
      publicKey: {
        challenge: _b64url2ab(resp.challenge),
        rp: { name: "KQLab", id: location.hostname },
        user: {
          id: new TextEncoder().encode(resp.userId),
          name: userLogin,
          displayName: userLogin
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 }
        ],
        timeout: 60000,
        attestation: "none",
        authenticatorSelection: {
          residentKey: "preferred",
          requireResidentKey: false,
          userVerification: "preferred"
        }
      }
    });

    if (!cred) throw new Error("Enregistrement annulé");

    var pubKeyBytes = cred.response.getPublicKey ? cred.response.getPublicKey() : null;
    if (!pubKeyBytes) throw new Error("Impossible de récupérer la clé publique (navigateur non supporté)");

    var regResp = await API.post("/auth/passkey/register", {
      credentialId: _ab2b64url(cred.rawId),
      publicKey: _ab2b64url(pubKeyBytes),
      clientDataJSON: _ab2b64url(cred.response.clientDataJSON)
    });
    if (regResp.error) throw new Error(regResp.error);
    return regResp;
  }
};
