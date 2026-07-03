package com.understory.aegis

import com.understory.security.BaseCapabilityProvider

/**
 * aegis's capability beacon. Consumers translate
 * `(com.understory.aegis, version=1)` into [SuiteCapability.OTP_STORE]
 * (storage only — aegis ships no peer-invocable code-issue surface at v1)
 * via their KNOWN_PEERS table.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
