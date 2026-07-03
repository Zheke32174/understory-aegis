package com.understory.aegis

import com.understory.security.BaseCapabilityProvider

/**
 * aegis's capability beacon. Consumers translate
 * `(com.understory.aegis, version=1)` into [SuiteCapability.OTP_VAULT]
 * via their KNOWN_PEERS table.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
