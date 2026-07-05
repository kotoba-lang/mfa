(ns mfa.core-test
  (:require [clojure.test :refer [deftest testing is]]
            [mfa.core :as mfa]))

(deftest evaluate-count-test
  (testing "satisfied by count alone"
    (let [p (mfa/policy {:min-factors 2})]
      (is (true? (:satisfied? (mfa/evaluate p [:password :totp]))))))
  (testing "unsatisfied by count"
    (let [p (mfa/policy {:min-factors 2})]
      (is (false? (:satisfied? (mfa/evaluate p [:password]))))
      (is (= 1 (:factor-count (mfa/evaluate p [:password])))))))

(deftest evaluate-required-methods-test
  (testing "count satisfied but a required method missing => unsatisfied"
    (let [p (mfa/policy {:min-factors 2 :required-methods #{:webauthn}})
          result (mfa/evaluate p [:password :totp])]
      (is (false? (:satisfied? result)))
      (is (= #{:webauthn} (:missing-required result)))))
  (testing "required method present and count satisfied => satisfied"
    (let [p (mfa/policy {:min-factors 2 :required-methods #{:webauthn}})
          result (mfa/evaluate p [:password :webauthn])]
      (is (true? (:satisfied? result)))
      (is (empty? (:missing-required result))))))

(deftest evaluate-allowed-methods-test
  (testing "a completed method outside allowed-methods does not count toward the total"
    (let [p (mfa/policy {:min-factors 2 :allowed-methods #{:totp :webauthn}})
          result (mfa/evaluate p [:password :sms])]
      (is (false? (:satisfied? result)))
      (is (= 0 (:factor-count result)))))
  (testing "allowed-methods restricts the count but a large enough intersection still satisfies"
    (let [p (mfa/policy {:min-factors 2 :allowed-methods #{:totp :webauthn}})
          result (mfa/evaluate p [:password :totp :webauthn])]
      (is (true? (:satisfied? result)))
      (is (= 2 (:factor-count result))))))

(deftest step-up-required-test
  (let [default-policy (mfa/policy {:min-factors 1})
        strict-policy (mfa/policy {:min-factors 2})
        amr [:password]]
    (testing "action has no override -> falls back to default policy (already satisfied)"
      (is (false? (mfa/step-up-required? default-policy amr {} :view-profile))))
    (testing "action has a stricter override -> step-up required"
      (is (true? (mfa/step-up-required? default-policy amr {:transfer-funds strict-policy} :transfer-funds))))
    (testing "action override satisfied by amr -> no step-up"
      (is (false? (mfa/step-up-required? default-policy [:password :totp]
                                          {:transfer-funds strict-policy} :transfer-funds))))))

(deftest remaining-suggestions-test
  (testing "already satisfied -> nil"
    (let [p (mfa/policy {:min-factors 1})]
      (is (nil? (mfa/remaining-suggestions p [:password] [:totp :webauthn])))))
  (testing "not satisfied -> suggests unused available methods"
    (let [p (mfa/policy {:min-factors 2})]
      (is (= #{:totp :webauthn}
             (mfa/remaining-suggestions p [:password] [:totp :webauthn])))))
  (testing "suggestions are filtered to available-methods actually enrolled"
    (let [p (mfa/policy {:min-factors 2})]
      (is (= #{:totp}
             (mfa/remaining-suggestions p [:password] [:totp])))))
  (testing "allowed-methods further restricts suggestions to what's both allowed and available"
    (let [p (mfa/policy {:min-factors 2 :allowed-methods #{:webauthn}})]
      (is (= #{}
             (mfa/remaining-suggestions p [:password] [:totp]))))))
