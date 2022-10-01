package pkigen

import (
	"encoding/json"
	"fmt"
)

func ExampleMarshalPublicKey() {

	// ALWAYS generate a new key - do not reuse this key
	k, _ := UnmarshalPrivateKey(
		&Base64EncodedRSAKey{
			PrivateKey: "MIIEowIBAAKCAQEA2_vOF24UnIu-EnlL-wnZiKOmsxJIr0ZSGMe6atPTP9GT1OEBZLMbZ5NBiSlD4nIhpvSrthxjrRjiIERUupk2if-oaPnBPbuwuKks8X6aidP_vWUaIQiKYYXzlEvoXWxnPOlvs_e9cqjDAowy6zodHvGcGTOH8nTcv0MN_PEdGhbv5E85HBjl0I2pja2gEFjFmid0IORff1po_bKepzrktDJdS6pNgQimOM4HcpBuQU8E4MSgKnXH0ONlj-qbsfiTA34QINaSFMqm-UrAyh_jUkr8zpu5pFZpqSb9XGxLtb8f2TFhyJEPR1i42VyLiV42q1f0cemQqqNAAaTjMKM_mQIDAQABAoIBAE77R3FuGoRiP-oOFtOZI7tFVpKwm9wiWVOAUlQMnaoqKvOhnYh0LgCwBDWk1TS2WZLCAeyuoLMDXhzLq8gbPlOpsOOP2Gu7uaVzSCmklQOrVATCCfGWSWjeWSgDYPg59Y8PGQX6itBh-zIs-BMwmEgF40_BCqxofOFGx_zq7NHyg3uNcJ4AF0CXCrasVNrLjppx0ae8hbHy2SfKdIYasgnuMnUrW30cQFYZzmBrMuxuRRcBzRKDzClL2_flmIj5v1B3KoLz5xOXTysg4HG1tg4NZ0GqJPgwxcCvNhE-wTDEI2QKr_rCI48mLsJoIrb6vi6bRb4Gg_qTyPX9WpD1JukCgYEA3Ymno84CFXUd19AXUZosqWL8xm08S67UsdAdGtpr0JcJZv68ImJFeWLwS6kdBmWXdmt0bQqu5m3hxu1c-TImB5-kzV40s-Xm6hw5De-A7Y24rDYt3gR84ox7dAOUC-pCv83fXXzc6YkNBh3wRuQEzijxXMOGNXsbBEm3863tsLsCgYEA_jRCyqS_0-WE49j4jjnwCfWUQRrszMlbiKCsjf_HLacXM8GQI3_P-citqWXRoZylJzeuSWcCA-g3rZuumHvWXvoG9343T8BTWwGrBTqZpz2U7viMEywzddGywKIDSN-vmGCjay4yU7qT4BKJvXE4MM_vhV4MpQwRGvN_3wN2hbsCgYBphxLV0mHnurwWe0dAVcKEhWSHWK1qF8O1V78ldXn6CJgv-ZPAhTM22UxBnjL3QxldDV6OOpKJrTnpOlQZWCwJYaBtOzy7nP3b8smyu62ceu_HCJ_crCKY__YmkzXIXzSgjP6jV8EbdW9AxK4Z9q_bTGF8oJ6jhxqddkgryWP51QKBgQCVqb09Q7wxDGuuHhtQ2Wmq42xy3GBYvaBnk3mkbNge18aAUVEEpYaUIIOmPW0rwmc17MFvM_dqx3iofQVRf2-aIYiihCwahzhMV3ISNQsr_MTH4YvO6fIuRtUANyLJ7_CZPSRZwSweQbY4cZGo-JTFoFb75YB6V91mScCaU5afawKBgDgZTwOoA3fDujfkAdiqiDS5s-MSKD9slHByX5lvxt_ERWMJwUHUHoDqy0uJsvHx0qlqorkFHcSgiXNSYWDtbvcWH-tV3gPhWSEI0gBqgcy4uKNRBALJOhC5Ew-X4NkL_FOYeRgMYn9AE2aVybbdM2JTpola8HtLP3TlY-RFUAqJ",
		},
	)

	// Return struct containing public key only, base64 encoded
	j, _ := MarshalPublicKey(k)

	// Serialise
	b, _ := json.Marshal(j)

	fmt.Println(string(b))
	// Output: {"public_key":"MIIBCgKCAQEA2_vOF24UnIu-EnlL-wnZiKOmsxJIr0ZSGMe6atPTP9GT1OEBZLMbZ5NBiSlD4nIhpvSrthxjrRjiIERUupk2if-oaPnBPbuwuKks8X6aidP_vWUaIQiKYYXzlEvoXWxnPOlvs_e9cqjDAowy6zodHvGcGTOH8nTcv0MN_PEdGhbv5E85HBjl0I2pja2gEFjFmid0IORff1po_bKepzrktDJdS6pNgQimOM4HcpBuQU8E4MSgKnXH0ONlj-qbsfiTA34QINaSFMqm-UrAyh_jUkr8zpu5pFZpqSb9XGxLtb8f2TFhyJEPR1i42VyLiV42q1f0cemQqqNAAaTjMKM_mQIDAQAB"}
}
