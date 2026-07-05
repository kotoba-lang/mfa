# kotoba-lang/mfa

[![CI](https://github.com/kotoba-lang/mfa/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/mfa/actions/workflows/ci.yml)

Multi-factor **policy** as pure `.cljc` data — decides whether a set of
already-completed authentication methods satisfies a requirement. This repo
implements **zero factors itself**. It only asks: given what already
happened, is that combination enough?

The actual factors live in their own repos, all producing/consuming the same
`amr` (Authentication Methods References) keyword-set convention:

- `kotoba-lang/authentication` — password/OTP orchestration, the source of a
  session's `amr`
- `kotoba-lang/onetime` — TOTP/HOTP
- `org-w3-webauthn` — WebAuthn
- `com-apple-touchid` / `com-apple-faceid` — platform biometrics
- `org-ietf-oauth2` / `org-openid-oidc` / `org-oasis-saml` — federated auth

None of those are code dependencies of this repo — the only contract is the
shared `amr` shape (a collection of method keywords, e.g. `[:password :totp]`).

## Usage

```clojure
(require '[mfa.core :as mfa])

(def default-policy (mfa/policy {:min-factors 2}))

(mfa/evaluate default-policy [:password :totp])
;; => {:satisfied? true, :missing-required #{}, :factor-count 2, :min-factors 2}

;; Step-up: a specific action can demand a stricter policy than the login satisfied
(def transfer-policy (mfa/policy {:min-factors 2 :required-methods #{:webauthn}}))

(mfa/step-up-required? default-policy [:password :totp]
                        {:transfer-funds transfer-policy} :transfer-funds)
;; => true — the session has 2 factors, but none is webauthn

(mfa/remaining-suggestions transfer-policy [:password :totp] [:webauthn :sms])
;; => #{:webauthn} — only methods actually enrolled (available-methods) are suggested
```

## Test

```bash
clojure -M:test
```
