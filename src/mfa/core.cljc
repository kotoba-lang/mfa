(ns mfa.core
  "Multi-factor policy evaluation as pure data — decides whether a set of
  already-completed authentication methods (the OIDC 'amr' concept, see
  `kotoba-lang/authentication`) satisfies a policy.

  Does not implement any factor itself: password/OTP verification lives in
  `kotoba-lang/authentication`, TOTP/HOTP in `kotoba-lang/onetime`,
  WebAuthn/OAuth2/OIDC/SAML/biometrics in their own repos
  (`org-w3-webauthn`, `org-ietf-oauth2`, `org-openid-oidc`, `org-oasis-saml`,
  `com-apple-touchid`, `com-apple-faceid`). This repo only asks: given the
  methods already completed, is that combination enough?"
  (:require [clojure.set :as set]))

(defn policy
  "Build a policy map. `min-factors` (default 2) is how many distinct
  methods must be present, counted only among `allowed-methods` when that
  set is non-empty (empty/nil means any completed method counts).
  `required-methods` must ALL be present regardless of the count — e.g.
  `#{:webauthn}` for a policy that always demands a hardware key on top of
  whatever else satisfies the count."
  [{:keys [min-factors allowed-methods required-methods]
    :or {min-factors 2}}]
  {:min-factors min-factors
   :allowed-methods (set allowed-methods)
   :required-methods (set required-methods)})

(defn completed-methods
  "`amr` (Authentication Methods References) is conventionally an ordered
  vector — see `kotoba-lang/authentication` — but policy evaluation only
  cares which methods occurred, not the order they occurred in, so this
  collapses it to a set."
  [amr]
  (set amr))

(defn evaluate
  "Pure decision, never throws. Returns
  {:satisfied? bool :missing-required #{...} :factor-count n :min-factors n}."
  [policy amr]
  (let [methods (completed-methods amr)
        allowed (:allowed-methods policy)
        counted (if (seq allowed)
                  (set/intersection methods allowed)
                  methods)
        missing-required (set/difference (:required-methods policy) methods)]
    {:satisfied? (and (empty? missing-required)
                       (>= (count counted) (:min-factors policy)))
     :missing-required missing-required
     :factor-count (count counted)
     :min-factors (:min-factors policy)}))

(defn step-up-required?
  "Looks up the policy for `action` in `action->policy` (falling back to
  `policy` when absent) and evaluates it against `amr`. Returns true when
  the action's policy is NOT satisfied by what's already completed — i.e.
  the caller should prompt for additional factors before proceeding."
  [policy amr action->policy action]
  (let [effective-policy (get action->policy action policy)]
    (not (:satisfied? (evaluate effective-policy amr)))))

(defn remaining-suggestions
  "When `policy` is not yet satisfied by `amr`, returns the subset of
  `available-methods` not yet completed that would count toward
  satisfying it (respecting `allowed-methods` when set). Returns nil when
  already satisfied."
  [policy amr available-methods]
  (let [result (evaluate policy amr)]
    (when-not (:satisfied? result)
      (let [allowed (:allowed-methods policy)
            candidates (if (seq allowed) allowed (set available-methods))]
        (set/difference (set/intersection candidates (set available-methods))
                         (completed-methods amr))))))
